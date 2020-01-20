#
# This module implements simple IDA utilities
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_search
import ida_ua
import idaapi
import idc


def find_bytes(
        search: str,
        address: int = 0,
        forward_search: bool = True) -> int:
    # IDA 9.0
    if idaapi.IDA_SDK_VERSION >= 900:
        if forward_search:
            address = ida_bytes.find_bytes(search, address)
        else:
            address = ida_bytes.find_bytes(
                search,
                range_start=0,
                range_end=address,
                flags=ida_bytes.BIN_SEARCH_BACKWARD
            )
    # IDA 8.4
    elif idaapi.IDA_SDK_VERSION == 840:
        if forward_search:
            address = ida_search.find_binary(address, -1, search, 0x10, ida_search.SEARCH_DOWN)
        else:
            address = ida_search.find_binary(0, address, search, 0x10, ida_search.SEARCH_UP)
    else:
        print("[WARNING] Unsupported IDA version. Supported versions: IDA 8.4+")
        return ida_idaapi.BADADDR

    return address


def Is64bit() -> bool:
    return ida_ida.inf_is_64bit()


def Is32bit() -> bool:
    return ida_ida.inf_is_32bit_exactly()


def GetProcessorWordSize() -> int:
    if Is64bit() is True:
        return 8
    elif Is32bit() is True:
        return 4
    else:
        raise Exception("Unsupported word size!")


def GetCustomWord(addr: int, wordSize: int = 4) -> int:
    if wordSize == 8:
        return Qword(addr)
    elif wordSize == 4:
        return Dword(addr)
    else:
        raise Exception("Unsupported word size!")


def MakeCustomWord(addr: int, wordSize: int = 4) -> None:
    if wordSize == 8:
        MakeQword(addr)
    elif wordSize == 4:
        MakeDword(addr)
    else:
        raise Exception("Unsupported word size!")


def GetProcessorWord(addr: int) -> int:
    wordSize = GetProcessorWordSize()
    if wordSize == 8:
        return Qword(addr)
    elif wordSize == 4:
        return Dword(addr)
    else:
        raise Exception("Unsupported word size!")


def MakeProccesorWord(addr: int) -> None:
    wordSize = GetProcessorWordSize()
    if wordSize == 8:
        MakeQword(addr)
    elif wordSize == 4:
        MakeDword(addr)
    else:
        raise Exception("Unsupported word size!")


def Byte(addr: int) -> int:
    return ida_bytes.get_wide_byte(addr)


def Word(addr: int) -> int:
    return ida_bytes.get_wide_word(addr)


def Dword(addr: int) -> int:
    return ida_bytes.get_wide_dword(addr)


def Qword(addr: int) -> int:
    return ida_bytes.get_qword(addr)


def MakeByte(addr: int) -> None:
    ida_bytes.create_data(addr, ida_bytes.FF_BYTE, 1, ida_idaapi.BADADDR)


def MakeWord(addr: int) -> None:
    ida_bytes.create_data(addr, ida_bytes.FF_WORD, 2, ida_idaapi.BADADDR)


def MakeDword(addr: int) -> None:
    ida_bytes.create_data(addr, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)


def MakeQword(addr: int) -> None:
    ida_bytes.create_data(addr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)


def GetStr(addr: int, strType: int, strLen: int = -1) -> bytes | None:
    return ida_bytes.get_strlit_contents(addr, strLen, strType)


def GetStr_PASCAL(addr: int) -> bytes | None:
    return GetStr(addr, ida_nalt.STRTYPE_PASCAL, Byte(addr) + 1).decode()


def MakeStr(startAddr: int, endAddr: int = ida_idaapi.BADADDR) -> None:
    idc.create_strlit(startAddr, endAddr)


def MakeStr_PASCAL(startAddr: int) -> None:
    oldStringType = idc.get_inf_attr(ida_ida.INF_STRTYPE)
    idc.set_inf_attr(ida_ida.INF_STRTYPE, ida_nalt.STRTYPE_PASCAL)
    MakeStr(startAddr, startAddr + Byte(startAddr) + 1)
    idc.set_inf_attr(ida_ida.INF_STRTYPE, oldStringType)


def FindRef_Dword(
        fromAddr: int,
        dwordToFind: int,
        flag: int = ida_bytes.BIN_SEARCH_FORWARD) -> int:
    stringToFind = str()

    for i in range(4):
        stringToFind += "%02X " % ((dwordToFind >> 8*i) & 0xff)

    if flag == ida_bytes.BIN_SEARCH_FORWARD:
        return find_bytes(stringToFind, fromAddr)
    else:
        return find_bytes(stringToFind, fromAddr, False)


def FindRef_Qword(
        fromAddr: int,
        qwordToFind: int,
        flag: int = ida_bytes.BIN_SEARCH_FORWARD) -> int:
    stringToFind = str()

    for i in range(8):
        stringToFind += "%02X " % ((qwordToFind >> 8*i) & 0xff)

    if flag == ida_bytes.BIN_SEARCH_FORWARD:
        return find_bytes(stringToFind, fromAddr)
    else:
        return find_bytes(stringToFind, fromAddr, False)


def FixName(name: str) -> str:
    name = "".join(i for i in name if ord(i) < 128)
    for elem in [".", "<", ">", ":", ",", "%"]:
        if elem in name:
            name = name.replace(elem, "_")
    return name


def MakeName(addr: int, name: str) -> None:
    name = FixName(name)
    # ida_idaapi.SN_FORCE == 0x800
    ida_name.set_name(
        addr,
        name,
        ida_name.SN_NOCHECK | ida_name.SN_NOWARN | 0x800
    )


def MakeFunction(addr: int) -> None:
    ida_funcs.del_func(addr)
    ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, 1)
    ida_ua.create_insn(addr)
    ida_auto.auto_wait()
    ida_funcs.add_func(addr)
