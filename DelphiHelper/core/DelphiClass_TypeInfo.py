#
# This module allows to parse and extract data from Delphi's TypeInfo
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_idaapi
import ida_name
from DelphiHelper.core.FieldEnum import FieldEnum
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


class TypeInfo(object):
    typeKindList = ["tkUnknown", "tkInteger", "tkChar", "tkEnumeration",
                    "tkFloat", "tkString", "tkSet", "tkClass", "tkMethod",
                    "tkWChar", "tkLString", "tkLWString", "tkVariant",
                    "tkArray", "tkRecord", "tkInterface", "tkInt64",
                    "tkDynArray", "tkUString", "tkClassRef", "tkPointer",
                    "tkProcedure", "tkMRecord"]

    def __init__(
            self,
            addr: int,
            fieldEnum: FieldEnum = None) -> None:
        self.__fieldEnum = fieldEnum
        self.__tableAddr = addr
        self.__processorWordSize = GetProcessorWordSize()

        if self.__tableAddr != 0:
            self.__typeName = GetStr_PASCAL(self.__tableAddr + 1)
            if self.__typeName is None:
                msg = ("TypeInfo: TypeName is None ("
                       + hex(self.__tableAddr)
                       + ").")
                raise DelphiHelperError(msg)

            self.__typeKind = Byte(self.__tableAddr)
            if self.__typeKind >= len(self.typeKindList):
                msg = ("TypeInfo: TypeKind out of range - "
                       + str(self.__typeKind)
                       + " ("
                       + hex(self.__tableAddr)
                       + ").")
                raise DelphiHelperError(msg)

            self.__typeDataAddr = self.__tableAddr + 2 + Byte(self.__tableAddr + 1)
            self.__propDataAddr = (self.__typeDataAddr
                                   + 2 * self.__processorWordSize
                                   + 3
                                   + Byte(self.__typeDataAddr + 2 * self.__processorWordSize + 2))

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def GetTypeName(self) -> str:
        return self.__typeName

    def MakeTable(self, resolveTypeInfoClass: int = 0) -> None:
        if ida_bytes.is_loaded(self.__tableAddr) and \
           self.__tableAddr != 0 and \
           "_TypeInfo" not in ida_name.get_name(self.__tableAddr):
            if resolveTypeInfoClass != 0:
                self.__ResolveTypeInfo(self.__tableAddr)
            else:
                self.__DeleteTable()
                self.__CreateTable()
                self.__ExtractData()

    def __ResolveTypeInfo(self, tableAddr: int) -> None:
        typeKind = Byte(tableAddr)

        if typeKind != 0xff:
            if self.typeKindList[typeKind] == "tkClass":
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
                        DelphiClass(classAddr).MakeClass()
            else:
                TypeInfo(tableAddr).MakeTable()

    def __CreatePropDataRecord_Class(self, addr: int) -> None:
        nameAddr = addr + 4 * self.__processorWordSize + 10
        recordSize = 4 * self.__processorWordSize + 11 + Byte(nameAddr)
        nextRecordAddr = addr + recordSize

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
        if ida_bytes.is_loaded(typeInfoAddr) and \
           typeInfoAddr != 0 and \
           "_TypeInfo" not in ida_name.get_name(typeInfoAddr):
            self.__ResolveTypeInfo(typeInfoAddr + self.__processorWordSize)

        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "PropType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "GetProc", 0)

        shiftCount = (self.__processorWordSize - 1) * 8
        bitmask = GetCustomWord(addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(addr, self.__processorWordSize),
                self.__typeName + "_Get" + GetStr_PASCAL(nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "SetProc", 0)

        bitmask = GetCustomWord(addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(addr, self.__processorWordSize),
                self.__typeName + "_Set" + GetStr_PASCAL(nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "StoredProc", 0)

        addr += self.__processorWordSize
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "Index", 0)

        addr += 4
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "Default", 0)

        addr += 4
        MakeWord(addr)
        ida_bytes.set_cmt(addr, "NameIndex", 0)

        MakeStr_PASCAL(nameAddr)
        ida_bytes.set_cmt(nameAddr, "Name", 0)

        MakeName(
            nextRecordAddr - recordSize,
            self.__typeName + "_" + GetStr_PASCAL(nameAddr)
        )

        return nextRecordAddr

    def __CreateTypeData_Class(self) -> None:
        addr = self.__typeDataAddr

        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.ClassType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.ParentInfo", 0)

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
        if ida_bytes.is_loaded(typeInfoAddr) and \
           typeInfoAddr != 0 and \
           "_TypeInfo" not in ida_name.get_name(typeInfoAddr):
            self.__ResolveTypeInfo(typeInfoAddr + self.__processorWordSize)

        addr += self.__processorWordSize
        MakeWord(addr)
        ida_bytes.set_cmt(addr, "TypeData.PropCount", 0)

        addr += 2
        MakeStr_PASCAL(addr)
        ida_bytes.set_cmt(addr, "TypeData.UnitName", 0)

        MakeWord(self.__propDataAddr)
        ida_bytes.set_cmt(self.__propDataAddr, "TypeData.PropData.PropCount", 0)

        propCount = Word(self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__CreatePropDataRecord_Class(addr)

        propCount = Word(addr)

        if propCount != 0 and propCount <= 0xff:
            if (Byte(addr + 2) == 2) or (Byte(addr + 2) == 3):
                MakeWord(addr)
                addr += 2

                for i in range(propCount):
                    MakeByte(addr)
                    MakeCustomWord(addr + 1, self.__processorWordSize)

                    nameAddr = GetCustomWord(addr + 1, self.__processorWordSize)
                    name = ida_name.get_name(nameAddr)
                    if self.__typeName not in name:
                        propDataRecordAddr = GetCustomWord(
                            addr + 1,
                            self.__processorWordSize
                        )
                        self.__CreatePropDataRecord_Class(propDataRecordAddr)

                    MakeWord(addr + 1 + self.__processorWordSize)
                    addr += (1 + self.__processorWordSize
                             + Word(addr + 1 + self.__processorWordSize))

    def __CreateTableHeader(self) -> None:
        MakeByte(self.__tableAddr)

        if self.__typeKind < len(self.typeKindList):
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - " + self.typeKindList[self.__typeKind],
                0
            )
        else:
            ida_bytes.set_cmt(
                self.__tableAddr,
                "Type kind - UNKNOWN",
                0
            )

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

        if self.typeKindList[self.__typeKind] == "tkClass":
            self.__CreateTypeData_Class()

    def __DeletePropDataRecord_Class(self, addr: int) -> int:
        recordSize = (4 * self.__processorWordSize
                      + 11
                      + Byte(addr + 4 * self.__processorWordSize + 10))
        ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
        return addr + recordSize

    def __DeleteTypeData_Class(self) -> None:
        size = (2 * self.__processorWordSize
                + 5
                + Byte(self.__typeDataAddr + 2 * self.__processorWordSize + 2))

        ida_bytes.del_items(
            self.__typeDataAddr,
            ida_bytes.DELIT_DELNAMES,
            size
        )

        propCount = Word(self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__DeletePropDataRecord_Class(addr)

        propCount = Word(addr)

        if propCount != 0:
            if Byte(addr + 2) == 2 or Byte(addr + 2) == 3:
                ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
                addr += 2

                for i in range(propCount):
                    ida_bytes.del_items(
                        addr,
                        ida_bytes.DELIT_DELNAMES,
                        3 + self.__processorWordSize
                    )

                    propDataRecordAddr = GetCustomWord(
                        addr + 1,
                        self.__processorWordSize
                    )
                    self.__DeletePropDataRecord_Class(propDataRecordAddr)

                    addr += (self.__processorWordSize
                             + 1
                             + Word(addr + self.__processorWordSize + 1))

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

        if self.typeKindList[self.__typeKind] == "tkClass":
            self.__DeleteTypeData_Class()

    def __ExtractData_PropDataRecord_Class(self, addr: int) -> int:
        nameAddr = addr + 4 * self.__processorWordSize + 10
        getProcEntry = GetCustomWord(
            addr + self.__processorWordSize,
            self.__processorWordSize
        )
        setProcEntry = GetCustomWord(
            addr + 2 * self.__processorWordSize,
            self.__processorWordSize
        )
        recordSize = 4 * self.__processorWordSize + 11 + Byte(nameAddr)
        shiftVal = (self.__processorWordSize - 1) * 8

        if self.__processorWordSize == 4:
            mask1 = 0x00FFFFFF
        else:
            mask1 = 0x00FFFFFFFFFFFFFF

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)

        if ida_bytes.is_loaded(typeInfoAddr) and typeInfoAddr != 0:
            typeInfo = TypeInfo(typeInfoAddr + self.__processorWordSize)
            typeName = typeInfo.GetTypeName()

            if ((getProcEntry >> shiftVal) & 0xF0 != 0) and \
               ((setProcEntry >> shiftVal) & 0xF0 != 0):
                if getProcEntry == setProcEntry:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(nameAddr),
                        setProcEntry & mask1
                    )
                else:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(nameAddr) + "_Get",
                        getProcEntry & mask1
                    )
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(nameAddr) + "_Set",
                        setProcEntry & mask1
                    )
            else:
                if (getProcEntry >> shiftVal) & 0xF0 != 0:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(nameAddr),
                        getProcEntry & mask1
                    )
                if (setProcEntry >> shiftVal) & 0xF0 != 0:
                    self.__fieldEnum.AddMember(
                        typeName,
                        GetStr_PASCAL(nameAddr),
                        setProcEntry & mask1
                    )

        return addr + recordSize

    def __ExtractData_TypeData_Class(self) -> None:
        propCount = Word(self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__ExtractData_PropDataRecord_Class(addr)

        propCount = Word(addr)

        if propCount != 0 and \
           propCount <= 0xff and \
           (Byte(addr + 2) == 2 or Byte(addr + 2) == 3):
            addr += 2

            for i in range(propCount):
                propDataRecordAddr = GetCustomWord(
                    addr + 1,
                    self.__processorWordSize
                )
                self.__ExtractData_PropDataRecord_Class(propDataRecordAddr)

                addr += (self.__processorWordSize
                         + 1
                         + Word(addr + self.__processorWordSize + 1))

    def __ExtractData(self) -> None:
        if self.typeKindList[self.__typeKind] == "tkClass" and \
           self.__fieldEnum is not None:
            self.__ExtractData_TypeData_Class()
