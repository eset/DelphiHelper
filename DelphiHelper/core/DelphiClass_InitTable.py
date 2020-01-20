#
# This module allows to parse and extract data from Delphi's InitTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
from DelphiHelper.core.DelphiClass_TypeInfo import *
from DelphiHelper.util.ida import *


class InitTable(object):

    def __init__(
            self,
            classInfo: dict[str, str | dict[str, int]],
            fieldEnum: FieldEnum) -> None:
        self.__tableAddr = classInfo["Address"]["InitTable"]
        self.__fieldEnum = fieldEnum
        self.__tableName = classInfo["Name"]
        self.__processorWordSize = GetProcessorWordSize()

        if self.__tableAddr != 0:
            self.__fieldCount = Word(self.__tableAddr + 6)
            self.__fieldAddr = self.__tableAddr + 8

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()
            self.__ExtractData()

    def __CreateTable(self) -> None:
        MakeWord(self.__tableAddr)
        MakeWord(self.__tableAddr + 2)
        MakeWord(self.__tableAddr + 4)
        MakeWord(self.__tableAddr + 6)
        MakeName(self.__tableAddr, self.__tableName + "_InitTable")

        addr = self.__fieldAddr
        for i in range(self.__fieldCount):
            MakeWord(addr)
            MakeCustomWord(addr + 2, self.__processorWordSize)

            if self.__processorWordSize == 4:
                MakeWord(addr + 6)
                addr += 8
            else:
                MakeWord(addr + 10)
                MakeDword(addr + 12)
                addr += 16

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(self.__tableAddr, ida_bytes.DELIT_DELNAMES, 8)

        addr = self.__fieldAddr
        for i in range(self.__fieldCount):
            if self.__processorWordSize == 4:
                ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 8)
                addr += 8
            else:
                ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 16)
                addr += 16

    def __ExtractData(self) -> None:
        if self.__fieldCount != 0:
            addr = self.__fieldAddr

            for i in range(self.__fieldCount):
                typeInfoAddr = GetCustomWord(
                    addr + 2,
                    self.__processorWordSize
                )

                if ida_bytes.is_loaded(typeInfoAddr) and \
                   typeInfoAddr != 0:
                    typeInfo = TypeInfo(typeInfoAddr + self.__processorWordSize)
                    typeInfo.MakeTable(1)
                    fieldType = typeInfo.GetTypeName()
                    fieldValue = Word(addr + 2 + self.__processorWordSize)

                    self.__fieldEnum.AddMember(
                        fieldType,
                        hex(fieldValue),
                        fieldValue
                    )

                if self.__processorWordSize == 4:
                    addr += 8
                else:
                    addr += 16
