#
# IDA plugin definition
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_auto
import ida_idaapi
import ida_kernwin
from DelphiHelper.core.ClassResolver import ResolveClass, ResolveApplicationClass
from DelphiHelper.core.DFMParser import ParseDFMs
from DelphiHelper.core.EPFinder import *
from DelphiHelper.core.FormViewer import FormViewer
from DelphiHelper.core.IDRKBLoader import *
from DelphiHelper.util.delphi import LoadDelphiFLIRTSignatures
from DelphiHelper.util.exception import DelphiHelperError


PLUGIN_NAME = "DelphiHelper"
PLUGIN_VERSION = "1.20"
PLUGIN_AUTHOR = "Juraj Hornak (juraj.hornak@eset.com)"


class DelphiHelperPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_MULTI
    comment = PLUGIN_NAME + " - IDA plugin simplifying the analysis of Delphi x86/x64 binaries"
    help = "IDA plugin simplifying the analysis of Delphi binaries"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt+Shift+H"

    def init(self):
        addon = ida_kernwin.addon_info_t()
        addon.id = "delphi_helper"
        addon.name = PLUGIN_NAME
        addon.producer = PLUGIN_AUTHOR
        addon.url = "juraj.hornak@eset.com"
        addon.version = PLUGIN_VERSION
        ida_kernwin.register_addon(addon)

        LoadDelphiFLIRTSignatures()

        return DelphiHelperPluginMain()


class DelphiHelperPluginMain(ida_idaapi.plugmod_t):

    def __init__(self) -> None:
        ida_idaapi.plugmod_t.__init__(self)

        self.__delphiFormList = list()
        self.__packageinfo = None
        self.__parseFlag = True

        self.hotkeys = []
        self.hotkeys.append(ida_kernwin.add_hotkey("Alt+Shift+R", self.resolveClass))
        self.hotkeys.append(ida_kernwin.add_hotkey("Alt+Shift+E", self.findEntryPointFunc))
        self.hotkeys.append(ida_kernwin.add_hotkey("Alt+Shift+F", self.formViewer))
        self.hotkeys.append(ida_kernwin.add_hotkey("Alt+Shift+S", self.loadIDRKBSignatures_main))
        self.hotkeys.append(ida_kernwin.add_hotkey("Alt+Shift+A", self.loadIDRKBSignatures_custom))

    def run(self, arg):
        self.printHelp()

    def printHelp(self) -> None:
        print("-"*100)
        print(f"{PLUGIN_NAME} ({PLUGIN_VERSION}) by {PLUGIN_AUTHOR}")
        print("Copyright (c) 2020-2024 ESET\n")
        print("IDA plugin simplifying the analysis of Delphi x86/x64 binaries")
        print("\nHotkeys:")

        print("  \"Alt + Shift + R\" - run VMT Parser in order to parse selected VMT structure")
        print("        Usage: Press it in disassembly window when the cursor is on the starting address of a VMT structure")
        print("               e.g.  mov edx, VMT_offset  --> starting address of the VMT structure")
        print("                     call CreateForm\n")

        print("  \"Alt + Shift + F\" - run DFM Finder (show Delphi Form Viewer)")
        print("        Usage: Press it anywhere in the disassembly window")
        print("        Note: The resource section of Delphi file must be loaded by IDA\n")

        print("  \"Alt + Shift + E\" - run Entry Point Function Finder (searching for \"CreateForm\", \"InitExe\" and \"InitLib\" references)")
        print("        Usage: Press it anywhere in the disassembly window\n")

        print("  \"Alt + Shift + S\" - run IDR Knowledge Base Loader for \"SysInit\" and \"System\" unit")
        print("        Usage: Press it anywhere in the disassembly window")
        print("        Note: read the README.md for KB file location.\n")

        print("  \"Alt + Shift + A\" - run IDR Knowledge Base Loader for selected units")
        print("        Usage: Press it anywhere in the disassembly window")
        print("        Note: read the README.md for KB file location.")
        print("-"*100)

    def term(self) -> None:
        for hotkey in self.hotkeys:
            ida_kernwin.del_hotkey(hotkey)

    def findEntryPointFunc(self) -> None:
        msg = "NODELAY\nHIDECANCEL\nSearching for EP function..."
        ida_kernwin.show_wait_box(msg)
        try:
            EPFinder().FindEPFunction()
        except DelphiHelperError as e:
            e.print()
        finally:
            ida_kernwin.hide_wait_box()

    def resolveClass(self) -> None:
        msg = "NODELAY\nHIDECANCEL\nProcessing selected VMT structure..."
        ida_kernwin.show_wait_box(msg)
        try:
            LoadDelphiFLIRTSignatures()
            ida_auto.auto_wait()
            ResolveClass(ida_kernwin.get_screen_ea())
        except DelphiHelperError as e:
            e.print()
        finally:
            ida_kernwin.hide_wait_box()

    def formViewer(self) -> None:
        msg = "NODELAY\nHIDECANCEL\nProcessing Delphi file's DFMs..."
        ida_kernwin.show_wait_box(msg)
        try:
            LoadDelphiFLIRTSignatures()
            ida_auto.auto_wait()
            ResolveApplicationClass()

            if self.__parseFlag:
                self.__delphiFormList = ParseDFMs()
                self.__parseFlag = False

            if self.__delphiFormList:
                FormViewer(self.__delphiFormList)
            else:
                print("[INFO] The Delphi binary seems to not contain any Delphi Form")
        except DelphiHelperError as e:
            e.print()
        finally:
            ida_kernwin.hide_wait_box()

    def loadIDRKBSignatures_custom(self) -> None:
        try:
            KBLoader()
        except DelphiHelperError as e:
            e.print()

    def loadIDRKBSignatures_main(self) -> None:
        try:
            IDRKBLoader(["SysInit", "System"]).LoadIDRKBSignatures()
        except DelphiHelperError as e:
            e.print()


def PLUGIN_ENTRY():
    """Required plugin entry point for IDAPython Plugins.
    """

    return DelphiHelperPlugin()
