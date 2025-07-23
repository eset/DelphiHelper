#
# This module allows to parse and extract data from Delphi's TypeInfo
#
# Copyright (c) 2020-2025 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_idaapi
import ida_name
from DelphiHelper.core.DelphiClass_TypeInfo_tkClass import TypeInfo_tkClass
from DelphiHelper.core.DelphiClass_TypeInfo_tkRecord import TypeInfo_tkRecord
from DelphiHelper.core.FieldEnum import FieldEnum
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


typeKindList = ["tkUnknown", "tkInteger", "tkChar", "tkEnumeration",
                "tkFloat", "tkString", "tkSet", "tkClass", "tkMethod",
                "tkWChar", "tkLString", "tkLWString", "tkVariant",
                "tkArray", "tkRecord", "tkInterface", "tkInt64",
                "tkDynArray", "tkUString", "tkClassRef", "tkPointer",
                "tkProcedure", "tkMRecord"]

def ParseTypeInfo(addr: int, delphiVersion: int) -> int:
    global typeKindList

    if Byte(addr) and \
       Byte(addr) < len(typeKindList) and \
       Dword(addr - GetProcessorWordSize()) == addr and \
       Byte(addr - GetProcessorWordSize() - 1) == 0:
        typeInfo = TypeInfo(delphiVersion, addr)
        typeInfo.MakeTable()

        if typeKindList[Byte(addr)] == "tkClass":
            typeInfo.ResolveTypeInfo(addr)

        addr += Byte(addr + 1)

    return addr + 1

class TypeInfo(object):

    def __init__(
            self,
            delphiVersion: int,
            addr: int = ida_idaapi.BADADDR,
            fieldEnum: FieldEnum = None) -> None:
        self.__delphiVersion = delphiVersion
        self.__fieldEnum = fieldEnum
        self.__tableAddr = addr
        self.__processorWordSize = GetProcessorWordSize()
        self.__typeName = ""

        if self.__tableAddr and self.__tableAddr != ida_idaapi.BADADDR:
            self.__typeName = GetStr_PASCAL(self.__tableAddr + 1)
            if self.__typeName is None:
                msg = ("TypeInfo: TypeName is None ("
                       + hex(self.__tableAddr)
                       + ").")
                raise DelphiHelperError(msg)

            global typeKindList
            self.__typeKind = Byte(self.__tableAddr)
            if self.__typeKind >= len(typeKindList):
                msg = ("TypeInfo: TypeKind out of range - "
                       + str(self.__typeKind)
                       + " ("
                       + hex(self.__tableAddr)
                       + ").")
                raise DelphiHelperError(msg)

            typeDataAddr = self.__tableAddr + 2 + Byte(self.__tableAddr + 1)

            if typeKindList[self.__typeKind] == "tkClass":
                self.__tkClass = TypeInfo_tkClass(
                    typeDataAddr,
                    self.__typeName,
                    self.__delphiVersion
                )
            elif typeKindList[self.__typeKind] == "tkRecord":
                self.__tkRecord = TypeInfo_tkRecord(
                    typeDataAddr,
                    self.__typeName,
                    self.__delphiVersion
                )

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def GetTypeName(self) -> str:
        return self.__typeName

    def MakeTable(self, resolveTypeInfoClass: int = 0) -> None:
        if self.__tableAddr and \
           self.__tableAddr != ida_idaapi.BADADDR and \
           ida_bytes.is_loaded(self.__tableAddr) and \
           "_TypeInfo" not in ida_name.get_name(self.__tableAddr):
            print(
                f"[INFO] Processing {self.__typeName}_TypeInfo (0x{self.__tableAddr:X})"
            )
            if resolveTypeInfoClass != 0:
                self.ResolveTypeInfo(self.__tableAddr)
            else:
                self.__DeleteTable()
                self.__CreateTable()
                self.__ExtractData()

    def ResolveTypeInfo(
            self,
            tableAddr: int,
            once: bool = False) -> None:
        if tableAddr == ida_idaapi.BADADDR or \
           tableAddr == 0 or \
           not ida_bytes.is_loaded(tableAddr):
            return

        if once:
            if "_TypeInfo" in ida_name.get_name(tableAddr) or \
               not ida_bytes.is_loaded(tableAddr + self.__processorWordSize):
                return
            tableAddr += self.__processorWordSize

        typeKind = Byte(tableAddr)

        global typeKindList
        if typeKind != 0xff:
            if typeKindList[typeKind] == "tkClass":
                self.__ResolveTypeInfo_tkClass(tableAddr)
            else:
                typeInfo = TypeInfo(
                    self.__delphiVersion,
                    tableAddr
                )
                typeInfo.MakeTable()

    def __ResolveTypeInfo_tkClass(self, tableAddr: int) -> None:
        if self.__processorWordSize == 4:
            ref = FindRef_Dword(
                tableAddr - 4,
                tableAddr,
                ida_bytes.BIN_SEARCH_BACKWARD
            )
        else:
            ref = FindRef_Qword(
                tableAddr - 4,
                tableAddr,
                ida_bytes.BIN_SEARCH_BACKWARD
            )

        if ref != ida_idaapi.BADADDR:
            classAddr = ref - 4 * self.__processorWordSize
            className = ida_name.get_name(classAddr)

            if not className.startswith("VMT_"):
                from DelphiHelper.core.DelphiClass import DelphiClass
                delphiClass = DelphiClass(
                    classAddr,
                    self.__delphiVersion
                )
                delphiClass.MakeClass()        

    def __CreateTableHeader(self) -> None:
        MakeByte(self.__tableAddr)

        global typeKindList
        if self.__typeKind < len(typeKindList):
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - " + typeKindList[self.__typeKind],
                0
            )
        else:
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - UNKNOWN",
                0
            )

        if Byte(self.__tableAddr + 1):
            MakeStr_PASCAL(self.__tableAddr + 1)
            ida_bytes.set_cmt(self.__tableAddr + 1, "Type name", 0)

            MakeName(self.__tableAddr, self.__typeName + "_TypeInfo")

            addr = GetCustomWord(
                self.__tableAddr - self.__processorWordSize,
                self.__processorWordSize
            )

            if addr == self.__tableAddr:
                MakeCustomWord(
                    self.__tableAddr - self.__processorWordSize,
                    self.__processorWordSize
                )
                MakeName(
                    self.__tableAddr - self.__processorWordSize,
                    "_" + self.__typeName + "_TypeInfo"
                )

    def __CreateTable(self) -> None:
        self.__CreateTableHeader()

        global typeKindList
        if typeKindList[self.__typeKind] == "tkClass":
            self.__tkClass.CreateTypeData()
        elif typeKindList[self.__typeKind] == "tkRecord":
            self.__tkRecord.CreateTypeData()

    def __DeleteTableHeader(self) -> None:
        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            1
        )
        ida_bytes.del_items(
            self.__tableAddr + 1,
            ida_bytes.DELIT_DELNAMES,
            1 + Byte(self.__tableAddr + 1)
        )

        addr = GetCustomWord(
            self.__tableAddr - self.__processorWordSize,
            self.__processorWordSize
        )

        if addr == self.__tableAddr:
            ida_bytes.del_items(
                self.__tableAddr - self.__processorWordSize,
                ida_bytes.DELIT_DELNAMES,
                self.__processorWordSize
            )

    def __DeleteTable(self) -> None:
        self.__DeleteTableHeader()

        global typeKindList
        if typeKindList[self.__typeKind] == "tkClass":
            self.__tkClass.DeleteTypeData()
        elif typeKindList[self.__typeKind] == "tkRecord":
            self.__tkRecord.DeleteTypeData()

    def __ExtractData(self) -> None:
        global typeKindList
        if typeKindList[self.__typeKind] == "tkClass":
            self.__tkClass.ExtractData_TypeData(self.__fieldEnum)
