#
# This module implements utilities for working with Delphi binaries
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
from DelphiHelper.util.ida import (
    Is32bit, Is64bit, GetStr_PASCAL, GetProcessorWordSize, GetProcessorWord,
    Byte, MakeStr_PASCAL, find_bytes, FindRef_Dword, FindRef_Qword, MakeName,
    FixName
)


def GetApplicationClassAddr() -> int:
    # TApplication#
    strTApplicationAddr = find_bytes("0C 54 41 70 70 6C 69 63 61 74 69 6F 6E")

    if strTApplicationAddr != ida_idaapi.BADADDR:
        if Is32bit():
            addr = FindRef_Dword(
                strTApplicationAddr,
                strTApplicationAddr,
                ida_bytes.BIN_SEARCH_BACKWARD
            )

            if addr != ida_idaapi.BADADDR:
                return addr - 0x20

        if Is64bit():
            addr = FindRef_Qword(
                strTApplicationAddr,
                strTApplicationAddr,
                ida_bytes.BIN_SEARCH_BACKWARD
            )

            if addr != ida_idaapi.BADADDR:
                return addr - 0x40

    return ida_idaapi.BADADDR


def LoadDelphiFLIRTSignatures() -> None:
    """Load Delphi 32bit FLIRT signatures"""
    sigList = ["bds8vcl", "bds8rw32", "bds8ext", "mssdk32"]
    loadedSigList = list()

    result = find_bytes(
        "20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 0D 0A"
    )
    result_2 = find_bytes("07 42 6F 6F 6C 65 61 6E")
    result_3 = find_bytes("05 46 61 6C 73 65")

    if ida_idaapi.BADADDR != result or \
       (ida_idaapi.BADADDR != result_2 and ida_idaapi.BADADDR != result_3):
        for i in range(ida_funcs.get_idasgn_qty()):
            loadedSigList.append(ida_funcs.get_idasgn_desc(i)[0])

        for sig in sigList:
            if sig not in loadedSigList:
                ida_funcs.plan_to_apply_idasgn(sig)


def GetUnits() -> list[str]:
    ida_kernwin.show_wait_box("Searching for imported Units...")
    units = list()
    initTableAddr = 0

    if Is64bit():
        initTableAddr = _findInitTable(40)
    elif IsExtendedInitTab():
        initTableAddr = _findInitTable(20)
    else:
        units = ["SysInit", "System"]

    if units == list():
        numOfUnits = GetProcessorWord(
            initTableAddr + 4 * GetProcessorWordSize()
        )
        addr = GetProcessorWord(initTableAddr + 5 * GetProcessorWordSize())

        for i in range(numOfUnits):
            unitName = GetStr_PASCAL(addr)
            units.append(unitName)
            ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, Byte(addr) + 1)
            MakeStr_PASCAL(addr)
            addr += Byte(addr) + 1

    ida_kernwin.hide_wait_box()

    return units


def FindInitTable() -> int:
    initTable = 0

    if Is64bit():
        initTable = _findInitTable(40)
    else:
        initTable = _findInitTable(4)

        if initTable == 0:
            initTable = _findInitTable(20)

    return initTable


def _findInitTable(offset: int) -> int:
    addr = ida_ida.inf_get_min_ea()
    maxAddr = ida_ida.inf_get_max_ea()
    initTable = 0

    procWordSize = GetProcessorWordSize()

    while addr < maxAddr - offset:
        initTable = GetProcessorWord(addr)

        if initTable == addr + offset:
            initTable -= offset + procWordSize
            num = GetProcessorWord(initTable)

            if num > 0 and num < 10000:
                pos = addr + offset

                for i in range(num):
                    funcAddr = GetProcessorWord(pos)

                    if funcAddr and not ida_bytes.is_loaded(funcAddr):
                        initTable = 0
                        break

                    funcAddr = GetProcessorWord(pos + procWordSize)

                    if funcAddr and not ida_bytes.is_loaded(funcAddr):
                        initTable = 0
                        break

                    pos += 2 * procWordSize

                if initTable:
                    break

        initTable = 0
        addr += procWordSize

    return initTable


def IsExtendedInitTab() -> bool:
    if _findInitTable(4):
        return False
    if _findInitTable(20):
        return True
    else:
        return False


def DemangleFuncName(funcAddr: int) -> str:
    funcName = ida_name.get_name(funcAddr)

    if "@" in funcName:
        funcNameSplitted = funcName.split("$")
        names = funcNameSplitted[0]

        parameters = ""
        if "$" in funcName:
            parameters = funcNameSplitted[1]

        namesSplitted = names.split("@")

        if namesSplitted[-1] == "":
            if namesSplitted[-2] == "":
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
            elif parameters == "bctr":
                funcName = namesSplitted[-2] + "_Constructor"
            elif parameters == "bdtr":
                funcName = namesSplitted[-2] + "_Destructor"
            else:
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
        elif namesSplitted[-1] == "":
            funcName = namesSplitted[-3] + "_" + namesSplitted[-1]
        else:
            funcName = namesSplitted[-2] + "_" + namesSplitted[-1]

        MakeName(funcAddr, FixName(funcName))

    return ida_name.get_name(funcAddr)


def ParseMangledFunctionName(mang_func_name: str) -> str:
    func_name_splitted = mang_func_name.split("$")
    tmp = func_name_splitted[0]
    tmp_splitted = tmp.split("@")
    used_keywords = []
    new_function_name = ""
    last_iteration_inserted = False

    for name in tmp_splitted:
        if name == "":
            continue

        if last_iteration_inserted:
            new_function_name += "_"
            last_iteration_inserted = False

        if name not in used_keywords:
            new_function_name += name
            last_iteration_inserted = True
            used_keywords.append(name)

    return new_function_name
