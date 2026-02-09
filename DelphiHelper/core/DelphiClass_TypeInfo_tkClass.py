#
# This module allows to parse and extract data from Delphi's TypeInfo tkClass
#
# Copyright (c) 2020-2026 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_name
from DelphiHelper.core.ClassStruct import *
from DelphiHelper.core.FieldEnum import FieldEnum
from DelphiHelper.util.ida import *


class TypeInfo_tkClass(object):

    def __init__(
            self,
            typeDataAddr: int,
            typeName: str,
            delphiVersion: int) -> None:
        self.__delphiVersion = delphiVersion
        self.__fieldEnum = None
        self.__processorWordSize = GetProcessorWordSize()
        self.__typeName = typeName
        self.__typeDataAddr = typeDataAddr
        self.__propDataAddr = (typeDataAddr
                               + 2 * self.__processorWordSize
                               + 3
                               + Byte(typeDataAddr + 2 * self.__processorWordSize + 2))

    def CreateTypeData(self) -> None:
        addr = self.__typeDataAddr

        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.ClassType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.ParentInfo", 0)

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
        from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
        typeInfo = TypeInfo(self.__delphiVersion)
        typeInfo.ResolveTypeInfo(typeInfoAddr, True)

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
            addr = self.__CreatePropDataRecord(addr)

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
                        self.__CreatePropDataRecord(propDataRecordAddr)

                    MakeWord(addr + 1 + self.__processorWordSize)
                    addr += (1 + self.__processorWordSize
                             + Word(addr + 1 + self.__processorWordSize))

    def __CreatePropDataRecord(self, addr: int) -> None:
        nameAddr = addr + 4 * self.__processorWordSize + 10
        recordSize = 4 * self.__processorWordSize + 11 + Byte(nameAddr)
        nextRecordAddr = addr + recordSize

        typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
        from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
        typeInfo = TypeInfo(self.__delphiVersion)
        typeInfo.ResolveTypeInfo(typeInfoAddr, True)

        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.PropData.PropType", 0)

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.PropData.GetProc", 0)

        shiftCount = (self.__processorWordSize - 1) * 8
        bitmask = GetCustomWord(addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(addr, self.__processorWordSize),
                self.__typeName + "_Get" + GetStr_PASCAL(nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.PropData.SetProc", 0)

        bitmask = GetCustomWord(addr, self.__processorWordSize) >> shiftCount
        if bitmask & 0xC0 == 0:
            MakeName(
                GetCustomWord(addr, self.__processorWordSize),
                self.__typeName + "_Set" + GetStr_PASCAL(nameAddr)
            )

        addr += self.__processorWordSize
        MakeCustomWord(addr, self.__processorWordSize)
        ida_bytes.set_cmt(addr, "TypeData.PropData.StoredProc", 0)

        addr += self.__processorWordSize
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "TypeData.PropData.Index", 0)

        addr += 4
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "TypeData.PropData.Default", 0)

        addr += 4
        MakeWord(addr)
        ida_bytes.set_cmt(addr, "TypeData.PropData.NameIndex", 0)

        MakeStr_PASCAL(nameAddr)
        ida_bytes.set_cmt(nameAddr, "TypeData.PropData.Name", 0)

        MakeName(
            nextRecordAddr - recordSize,
            self.__typeName + "_" + GetStr_PASCAL(nameAddr)
        )

        return nextRecordAddr

    def DeleteTypeData(self) -> None:
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
            addr = self.__DeletePropDataRecord(addr)

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
                    self.__DeletePropDataRecord(propDataRecordAddr)

                    addr += (self.__processorWordSize
                             + 1
                             + Word(addr + self.__processorWordSize + 1))

    def __DeletePropDataRecord(self, addr: int) -> int:
        recordSize = (4 * self.__processorWordSize
                      + 11
                      + Byte(addr + 4 * self.__processorWordSize + 10))
        ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
        return addr + recordSize

    def ExtractData_TypeData(
            self,
            fieldEnum: FieldEnum,
            classStruct: ClassStruct) -> None:
        self.__fieldEnum = fieldEnum
        self.__classStruct = classStruct

        if self.__fieldEnum is None or self.__classStruct is None:
            return

        propCount = Word(self.__propDataAddr)
        addr = self.__propDataAddr + 2

        for i in range(propCount):
            addr = self.__ExtractData_PropDataRecord(addr)

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
                self.__ExtractData_PropDataRecord(propDataRecordAddr)

                addr += (self.__processorWordSize
                         + 1
                         + Word(addr + self.__processorWordSize + 1))

    def __ExtractData_PropDataRecord(self, addr: int) -> int:
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
            from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
            typeInfo = TypeInfo(
                self.__delphiVersion,
                typeInfoAddr + self.__processorWordSize
            )
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

            if ((getProcEntry >> shiftVal) == 0xFF):
                self.__classStruct.AddMember(
                    typeName,
                    GetStr_PASCAL(nameAddr),
                    getProcEntry & mask1
                )
            if ((setProcEntry >> shiftVal) == 0xFF):
                self.__classStruct.AddMember(
                    typeName,
                    GetStr_PASCAL(nameAddr),
                    setProcEntry & mask1
                )

        return addr + recordSize
