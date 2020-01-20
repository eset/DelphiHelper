#
# This module implements GUI for FormViewer
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_kernwin
from PyQt5 import QtGui, QtWidgets
from DelphiHelper.core.DelphiForm import DelphiObject, DelphiProperty


class FormViewerUI():

    def __init__(
            self,
            parent,
            delphiFormList: list[tuple[DelphiObject, list[tuple[str, int]], int]]
            ) -> None:
        super().__init__()
        self.parent = parent
        self.initUI(delphiFormList)

    def initUI(
            self,
            delphiFormList: list[tuple[DelphiObject, list[tuple[str, int]], int]]
            ) -> None:
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Delphi Forms (Hint: Bold nodes -> Delphi Events inside, Green nodes -> binary files inside)",))
        self.tree.setColumnWidth(0, 30)
        self.tree.itemDoubleClicked.connect(OnDoubleClickItem)
        self.tree.itemClicked.connect(OnClickItem)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)

        self.PopulateFormTree(delphiFormList)

    def BuildObject(
            self,
            parentNode,
            delphiObject: DelphiObject,
            methodList: list[tuple[str, int]],
            VMTAddr: int = 0,
            _type: int = 1002) -> None:
        propList = delphiObject.GetPropertyList()
        childObjList = delphiObject.GetChildObjectList()

        objNode = ObjectNodeTreeItem(parentNode, delphiObject, VMTAddr, _type)

        if propList != list():
            propertyNode = PropertyNodeTreeItem(objNode)

            for prop in propList:
                PropertyTreeItem(propertyNode, prop, methodList)

        if childObjList != list():
            for childObj in childObjList:
                self.BuildObject(objNode, childObj, methodList)

    def BuildForm(
            self,
            parentNode,
            delphiForm: tuple[DelphiObject, list[tuple[str, int]], int]
            ) -> None:
        self.BuildObject(
            parentNode,
            delphiForm[0],
            delphiForm[1],
            delphiForm[2],
            1001
        )

    def PopulateFormTree(
            self,
            delphiFormList: list[tuple[DelphiObject, list[tuple[str, int]], int]]
            ) -> None:
        self.tree.clear()

        for delphiForm in delphiFormList:
            self.BuildForm(self.tree, delphiForm)


class ObjectNodeTreeItem(QtWidgets.QTreeWidgetItem):

    def __init__(
            self,
            parent,
            delphiObject: DelphiObject,
            VMTAddr: int,
            _type: int) -> None:
        super(ObjectNodeTreeItem, self).__init__(parent, _type)

        self.setData(0, 0x100, delphiObject)
        self.setText(
            0,
            "%s (%s)" % (
                delphiObject.GetObjectName(),
                delphiObject.GetClassName()
            )
        )
        self.setData(0, 0x101, VMTAddr)

        if VMTAddr != 0:
            self.setData(0, 3, "Click to go to the Form's VMT structure")


class PropertyNodeTreeItem(QtWidgets.QTreeWidgetItem):

    def __init__(self, parent) -> None:
        super(PropertyNodeTreeItem, self).__init__(parent)
        self.setText(0, "Properties")


class PropertyTreeItem(QtWidgets.QTreeWidgetItem):

    def __init__(
            self,
            parent,
            prop: DelphiProperty,
            methodList: list[tuple[str, int]]) -> None:
        super(PropertyTreeItem, self).__init__(parent, 1000)

        self.setText(
            0,
            "%s (%s) = %s" % (
                prop.GetName(),
                prop.GetTypeAsString(),
                prop.GetValueAsString()
            )
        )

        self.setData(0, 0x100, prop)

        if prop.GetTypeAsString() == "Binary":
            self.__setBinaryPropertyItem()

        if prop.GetTypeAsString() == "Ident" and \
           prop.GetName().startswith("On"):
            self.__setEventPropertyItem(prop, methodList)

    def __setBinaryPropertyItem(self) -> None:
        self.setData(
            0,
            3,
            "The file has been saved into current working directory"
        )
        self.setForeground(0, QtGui.QBrush(QtGui.QColor("green")))

        node = self.parent()
        while node is not None:
            node.setForeground(0, QtGui.QBrush(QtGui.QColor("green")))

            if node != self.parent():
                cmtToAdd = "The component or its child component includes some binary file (follow green nodes to see binary file in \"Properties\")"
                cmt = node.data(0, 3)

                if cmt is None:
                    node.setData(0, 3, cmtToAdd)
                elif cmtToAdd not in cmt:
                    node.setData(0, 3, cmt + "\n" + cmtToAdd)

            node = node.parent()

    def __setEventPropertyItem(
            self,
            prop: DelphiProperty,
            methodList: list[tuple[str, int]]) -> None:
        myFont = QtGui.QFont()
        myFont.setBold(True)

        self.setData(0, 0x101, 0)

        for method in methodList:
            if method[0] == prop.GetValue().decode():
                self.setData(0, 3, "Double-click to go to the Event handler")
                self.setData(0, 0x101, method[1])
                self.setForeground(0, QtGui.QBrush(QtGui.QColor("blue")))
                self.setFont(0, myFont)

                node = self.parent()
                while node is not None:
                    node.setFont(0, myFont)

                    if node != self.parent():
                        cmtToAdd = "The component or its child component has some Event defined (follow bold nodes to see blue colored Event in \"Properties\")"
                        cmt = node.data(0, 3)

                        if cmt is None:
                            node.setData(0, 3, cmtToAdd)
                        elif cmtToAdd not in cmt:
                            node.setData(0, 3, cmt + "\n" + cmtToAdd)

                    node = node.parent()


def OnDoubleClickItem(item) -> None:
    if item.type() == 1000:
        propType = item.data(0, 0x100).GetTypeAsString()

        if propType == "Ident" and \
           item.data(0, 0x100).GetName().startswith("On"):
            ida_kernwin.jumpto(item.data(0, 0x101))


def OnClickItem(item) -> None:
    if item.type() == 1001 and item.data(0, 0x101) != 0:
        ida_kernwin.jumpto(item.data(0, 0x101))
