#
# This module allows to load IDR KB signatures and implements GUI for
# IDRKBLoader
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import os
from DelphiHelper.core.IDRKBParser import GetDelphiVersion, KBParser
from DelphiHelper.util.delphi import GetUnits, ParseMangledFunctionName
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import (
        find_bytes, FixName, MakeFunction, MakeName, Is64bit
)
from PyQt5 import QtGui, QtCore, QtWidgets


class IDRKBLoaderDialog(ida_kernwin.PluginForm):

    def OnCreate(self, form) -> None:
        msg = "NODELAY\nHIDECANCEL\nExtracting list of imported units..."
        ida_kernwin.show_wait_box(msg)
        unitList = sorted(GetUnits())
        ida_kernwin.hide_wait_box()

        if len(unitList):
            ChecklistDialog(
                self.__clink__,
                self.FormToPyQtWidget(form),
                unitList
            )

    def OnClose(self, form) -> None:
        global _KBLoader
        del _KBLoader

    def Show(self):
        return ida_kernwin.plgform_show(
            self.__clink__,
            self,
            "IDR Knowledge Base Loader",
            ida_kernwin.WOPN_PERSIST | 0x20
        )


def KBLoader() -> None:
    global _KBLoader

    try:
        _KBLoader
    except Exception:
        _KBLoader = IDRKBLoaderDialog()

    _KBLoader.Show()


class ChecklistDialog(QtWidgets.QDialog):

    def __init__(
            self,
            clink,
            parent,
            unitList: list[str],
            checked: bool = True) -> None:
        super(ChecklistDialog, self).__init__(parent)

        self.clink = clink
        self.parent = parent

        self.model = QtGui.QStandardItemModel()
        self.listView = QtWidgets.QListView()

        for unit in unitList:
            item = QtGui.QStandardItem(unit)
            item.setCheckable(True)
            item.setEditable(False)

            if checked:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)

            self.model.appendRow(item)

        self.listView.setModel(self.model)

        self.loadButton = QtWidgets.QPushButton("Load")
        self.cancelButton = QtWidgets.QPushButton("Cancel")
        self.selectButton = QtWidgets.QPushButton("Select All")
        self.unselectButton = QtWidgets.QPushButton("Unselect All")

        hbox = QtWidgets.QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self.loadButton)
        hbox.addWidget(self.cancelButton)
        hbox.addWidget(self.selectButton)
        hbox.addWidget(self.unselectButton)

        vbox = QtWidgets.QVBoxLayout(self)
        label = QtWidgets.QLabel("Select units whose IDR KB signatures will be loaded")
        label.setFont(QtGui.QFont("Arial", 8))
        vbox.addWidget(label)
        label = QtWidgets.QLabel("Warning: Loading signatures for all units can last very long time")
        label.setFont(QtGui.QFont("Arial", 8))
        vbox.addWidget(label)
        vbox.addWidget(self.listView)
        vbox.addLayout(hbox)

        self.parent.setLayout(vbox)

        self.loadButton.clicked.connect(self.onLoad)
        self.cancelButton.clicked.connect(self.onCanceled)
        self.selectButton.clicked.connect(self.select)
        self.unselectButton.clicked.connect(self.unselect)

    def onLoad(self) -> None:
        choices = list()

        for i in range(self.model.rowCount()):
            if self.model.item(i).checkState() == QtCore.Qt.Checked:
                choices.append(self.model.item(i).text())

        ida_kernwin.plgform_close(self.clink, 0x2)

        try:
            if choices:
                IDRKBLoader(choices).LoadIDRKBSignatures()
        except DelphiHelperError as e:
            e.print()

    def onCanceled(self) -> None:
        ida_kernwin.plgform_close(self.clink, 0x2)

    def select(self) -> None:
        for i in range(self.model.rowCount()):
            item = self.model.item(i)
            item.setCheckState(QtCore.Qt.Checked)

    def unselect(self) -> None:
        for i in range(self.model.rowCount()):
            item = self.model.item(i)
            item.setCheckState(QtCore.Qt.Unchecked)


class IDRKBLoader(object):

    def __init__(self, units: list[str]) -> None:
        self.__unitList = units

    def LoadIDRKBSignatures(self, delphiVersion: int = 0) -> None:
        if delphiVersion == 0:
            ida_kernwin.show_wait_box("NODELAY\nHIDECANCEL\nTrying to determine Delphi version...")
            delphiVersion = GetDelphiVersion()
            ida_kernwin.hide_wait_box()

        if delphiVersion != -1:
            self.__loadSignatures(
                self.__getKBFilePath(delphiVersion),
                self.__unitList
            )

    def __isDifferentFunctionName(
            self,
            origName: str,
            signatureName: str) -> bool:
        if origName.startswith("KB_"):
            if origName == signatureName or \
               origName == signatureName + "_0":
                return False
            else:
                return True

        if "@" in origName:
            origName = ParseMangledFunctionName(origName)

        if origName == signatureName[3:]:
            return False

        return True

    def __renameFunction(self, unit: str, function: tuple[str, str]) -> bool:
        funcAddr = find_bytes(function[1])
        if funcAddr != ida_idaapi.BADADDR:
            if function[0][0] == "@":
                functionName = FixName("KB_" + unit + "_" + function[0][1:])
            else:
                functionName = FixName("KB_" + unit + "_" + function[0])

            funcAddr2 = find_bytes(function[1], funcAddr + 1)
            if funcAddr2 == ida_idaapi.BADADDR:
                funcStruct = ida_funcs.get_func(funcAddr)
                if funcStruct:
                    funcAddr = funcStruct.start_ea
                else:
                    MakeFunction(funcAddr)
                    print(f"[INFO] Making a new function on 0x{funcAddr:x}")
                origFunctionName = ida_name.get_name(funcAddr)

                if not self.__isDifferentFunctionName(origFunctionName, functionName):
                    return False

                functionCmt = ida_funcs.get_func_cmt(funcAddr, 1)
                if not self.__isDifferentFunctionName(origFunctionName, functionName) or \
                   (functionCmt and functionName in functionCmt):
                    return False

                if origFunctionName.startswith("sub_") or \
                   origFunctionName.startswith("unknown_"):
                    print(
                        f"[INFO] Renaming: {origFunctionName} -> {functionName} ({funcAddr:x})"
                    )
                    MakeName(funcAddr, functionName)
                else:
                    cmt = ida_funcs.get_func_cmt(funcAddr, 1)
                    if cmt:
                        cmt = functionName + "\n" + cmt
                    else:
                        cmt = functionName

                    print(f"[INFO] Adding alternative name: {origFunctionName} -> {functionName} (0x{funcAddr:x})")
                    ida_funcs.set_func_cmt(funcAddr, cmt, 1)
                return True
        return False

    def __getKBFilePath(self, delphiVersion: int) -> str:
        if Is64bit():
            KBPath = os.path.join(
                os.path.dirname(__file__),
                "..",
                "IDR_KB",
                "IDR64",
                f"syskb{delphiVersion}.bin"
            )
        else:
            KBPath = os.path.join(
                os.path.dirname(__file__),
                "..",
                "IDR_KB",
                "IDR",
                f"kb{delphiVersion}.bin"
            )
        KBPath = os.path.normpath(KBPath)

        if not os.path.exists(KBPath):
            print(f"[WARNING] KB file \"{KBPath}\" not found!")

            msg = f"KB file \"{KBPath}\" not found!\nNote: read the README.md for KB file location."
            ida_kernwin.warning(msg)

            raise DelphiHelperError()

        return KBPath

    def __loadSignatures(
            self,
            KBFile: str,
            units: list[str]) -> None:
        ida_kernwin.show_wait_box("NODELAY\nLoading IDR Knowledge base signatures...")

        try:
            kb = KBParser(KBFile)
            counter = 0
            unitCounter = 0

            for unit in units:
                unitCounter += 1
                moduleID = kb.GetModuleID(unit)

                if moduleID != -1:
                    print(f"[INFO] Loading function signatures for \"{unit}\" unit")

                    firstIndex, lastIndex = kb.GetProcIdxs(moduleID)
                    functions = kb.GetFunctions(firstIndex, lastIndex)
                    i = 0

                    for func in functions:
                        i += 1

                        msg = (f"Loading IDR Knowledge base signatures... Unit {unit} ({unitCounter}/{len(units)}) - Function ({i}/{len(functions)})")
                        ida_kernwin.replace_wait_box(msg)

                        if self.__renameFunction(unit, func):
                            counter += 1

                        if ida_kernwin.user_cancelled():
                            print(f"[INFO] Applied signatures: {str(counter)}")
                            return
                else:
                    print(f"[INFO] KB file does not include signatures for \"{unit}\" module")

            print(f"[INFO] Applied signatures: {str(counter)}")
        except DelphiHelperError as e:
            e.print()
        finally:
            ida_kernwin.hide_wait_box()
