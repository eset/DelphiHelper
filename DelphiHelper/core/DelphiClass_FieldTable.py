#
# This module allows to parse and extract data from Delphi's FieldTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
from DelphiHelper.core.DelphiClass_ClassTable import *
from DelphiHelper.core.DelphiClass_TypeInfo import *
from DelphiHelper.util.ida import *


class FieldTable(object):

    def __init__(
            self,
            classInfo: dict[str, str | dict[str, int]],
            fieldEnum: FieldEnum) -> None:
        self.__tableAddr = classInfo["Address"]["FieldTable"]
        self.__classInfo = classInfo
        self.__fieldEnum = fieldEnum
        self.__tableName = classInfo["Name"]
        self.__NoNameCounter = 1
        self.__processorWordSize = GetProcessorWordSize()
        self.__classTableEntries = list()

        if self.__tableAddr != 0:
            self.__classTableAddr = GetCustomWord(
                self.__tableAddr + 2,
                self.__processorWordSize
            )

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTableAndExtractData()

    def __CreateExtendedTableAndExtractData(self, addr: int) -> None:
        MakeWord(addr)
        numOfEntries = Word(addr)
        addr += 2

        for i in range(numOfEntries):
            nameAddr = addr + 5 + self.__processorWordSize
            recordSize = (8 + self.__processorWordSize
                          + Byte(nameAddr)
                          + Word(addr + 6
                                 + self.__processorWordSize
                                 + Byte(nameAddr))
                          - 2)

            MakeByte(addr)

            MakeCustomWord(addr + 1, self.__processorWordSize)
            typeInfoAddr = GetCustomWord(addr + 1, self.__processorWordSize)

            if typeInfoAddr == 0 or ida_bytes.is_loaded(typeInfoAddr):
                if typeInfoAddr == 0:
                    typeName = "NoType"
                else:
                    typeInfo = TypeInfo(typeInfoAddr + self.__processorWordSize)
                    typeInfo.MakeTable(1)
                    typeName = typeInfo.GetTypeName()

                MakeDword(addr + 1 + self.__processorWordSize)
                offset = Dword(addr + 1 + self.__processorWordSize)

                if Byte(nameAddr) != 0:
                    MakeStr_PASCAL(nameAddr)
                    name = GetStr_PASCAL(nameAddr)
                else:
                    MakeByte(nameAddr)
                    name = "NoName" + str(self.__NoNameCounter)
                    self.__NoNameCounter += 1

                MakeWord(addr + 6
                         + self.__processorWordSize
                         + Byte(nameAddr))

                if name[0] == "F":
                    tempName = name[1:]
                else:
                    tempName = name

                self.__fieldEnum.AddMember(typeName, tempName, offset)
                addr = addr + recordSize
            else:
                return

    def __CreateTableAndExtractData(self) -> None:
        MakeWord(self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_FieldTable")

        ida_bytes.set_cmt(
            self.__tableAddr,
            "Number of records",
            0
        )

        MakeCustomWord(self.__tableAddr + 2, self.__processorWordSize)

        ida_bytes.set_cmt(
            self.__tableAddr + 2,
            "Class table",
            0
        )
        ida_bytes.set_cmt(
            self.__tableAddr + 2 + self.__processorWordSize,
            "Number of fields",
            0
        )

        classTable = ClassTable(self.__classTableAddr, self.__tableName)
        self.__classTableEntries = classTable.MakeTable()

        addr = self.__tableAddr + 2 + self.__processorWordSize
        numOfEntries = Word(self.__tableAddr)

        for i in range(numOfEntries):
            fieldClassInfo = None
            recordSize = 7 + Byte(addr + 6)

            MakeDword(addr)
            offset = Dword(addr)
            MakeWord(addr + 4)
            index = Word(addr + 4)

            if Byte(addr + 6) != 0:
                MakeStr_PASCAL(addr + 6)
                name = GetStr_PASCAL(addr + 6)
            else:
                MakeByte(addr + 6)
                name = "NoName" + str(self.__NoNameCounter)
                self.__NoNameCounter += 1

            if ida_bytes.is_loaded(self.__classTableEntries[index]) and \
               self.__classTableEntries[index] != 0:
                from DelphiHelper.core.DelphiClass import DelphiClass
                delphiClass = DelphiClass(self.__classTableEntries[index])
                fieldClassInfo = delphiClass.GetClassInfo()

                ida_bytes.set_cmt(
                    addr,
                    fieldClassInfo["FullName"],
                    0
                )

            MakeName(addr, self.__tableName + "_" + name)

            if name[0] == "F":
                tempName = name[1:]
            else:
                tempName = name

            if fieldClassInfo is None:
                self.__fieldEnum.AddMember(
                    "Unknown",
                    tempName,
                    offset
                )
            else:
                self.__fieldEnum.AddMember(
                    fieldClassInfo["Name"],
                    tempName,
                    offset
                )

            addr = addr + recordSize

        methodTableAddr = self.__classInfo["Address"]["MethodTable"]
        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (methodTableAddr != 0 and addr < methodTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr != 0 and addr < dynamicTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr == 0 and addr < classNameAddr):
            self.__CreateExtendedTableAndExtractData(addr)

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            2 + self.__processorWordSize
        )

        addr = self.__tableAddr + 2 + self.__processorWordSize
        numOfEntries = Word(self.__tableAddr)

        for i in range(numOfEntries):
            recordSize = 7 + Byte(addr + 6)
            ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
            addr = addr + recordSize

        methodTableAddr = self.__classInfo["Address"]["MethodTable"]
        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (methodTableAddr != 0 and addr < methodTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr != 0 and addr < dynamicTableAddr) or \
           (methodTableAddr == 0 and dynamicTableAddr == 0 and addr < classNameAddr):
            ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
            numOfEntries = Word(addr)
            addr += 2

            for i in range(numOfEntries):
                recordSize = (8 + self.__processorWordSize
                              + Byte(addr + 5 + self.__processorWordSize)
                              + Word(addr + 6 + self.__processorWordSize + Byte(addr + 5 + self.__processorWordSize))
                              - 2)

                ida_bytes.del_items(
                    addr,
                    ida_bytes.DELIT_DELNAMES,
                    recordSize
                )

                addr = addr + recordSize
