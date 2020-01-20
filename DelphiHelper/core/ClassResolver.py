#
# This module allows to parse and extract data from Delphi's VMT structures
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_idaapi
import ida_kernwin
import ida_name
from DelphiHelper.core.DelphiClass import DelphiClass
from DelphiHelper.util.delphi import GetApplicationClassAddr
from DelphiHelper.util.exception import DelphiHelperError


def ResolveApplicationClass(classAddr: int = ida_idaapi.BADADDR) -> None:
    if classAddr == ida_idaapi.BADADDR:
        classAddr = GetApplicationClassAddr()
        if classAddr == ida_idaapi.BADADDR:
            return

    classApplicationName = ida_name.get_name(classAddr)
    if not classApplicationName.startswith('VMT_'):
        msg = "NODELAY\nHIDECANCEL\nProcessing \"TApplication\" VMT structure..."
        ida_kernwin.show_wait_box(msg)
        try:
            DelphiClass(classAddr).MakeClass()
        except DelphiHelperError:
            pass
        finally:
            ida_kernwin.hide_wait_box()


def ResolveClass(classAddr: int) -> None:
    ResolveApplicationClass()
    DelphiClass(classAddr).MakeClass()
