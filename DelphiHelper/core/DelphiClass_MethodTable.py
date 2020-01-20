#
# This module allows to parse Delphi's MethodTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.

import ida_bytes
import ida_name
import idc
from DelphiHelper.core.DelphiClass_TypeInfo import *
from DelphiHelper.util.ida import *


class MethodTable(object):

    def __init__(self, classInfo: dict[str, str | dict[str, int]]) -> None:
        self.__tableAddr = classInfo["Address"]["MethodTable"]
        self.__tableName = classInfo["Name"]
        self.__classInfo = classInfo
        self.__processorWordSize = GetProcessorWordSize()

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()

    def GetMethods(self) -> list[tuple[str, int]]:
        methodList = list()

        if self.__tableAddr != 0:
            numOfEntries = Word(self.__tableAddr)
            addr = self.__tableAddr + 2

            for i in range(numOfEntries):
                methodAddr = GetCustomWord(addr + 2, self.__processorWordSize)
                methodName = GetStr_PASCAL(addr + 2 + self.__processorWordSize)
                addr += Word(addr)
                methodList.append((methodName, methodAddr))

        return methodList

    def __CreateTable(self) -> None:
        MakeWord(self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_MethodTable")

        ida_bytes.set_cmt(
            self.__tableAddr,
            "Number of records",
            0
        )

        numOfEntries = Word(self.__tableAddr)
        if numOfEntries != 0:
            ida_bytes.set_cmt(
                self.__tableAddr + 2,
                "Record size",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 4,
                "Method pointer",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 4 + self.__processorWordSize,
                "Method Name",
                0
            )

        addr = self.__tableAddr + 2
        for i in range(numOfEntries):
            recordSize = Word(addr)

            MakeWord(addr)
            MakeFunction(GetCustomWord(addr + 2, self.__processorWordSize))
            MakeCustomWord(addr + 2, self.__processorWordSize)
            MakeStr_PASCAL(addr + 2 + self.__processorWordSize)

            name = (self.__tableName
                    + "_"
                    + GetStr_PASCAL(addr + 2 + self.__processorWordSize))

            MakeName(GetCustomWord(addr + 2, self.__processorWordSize), name)

            addr = addr + recordSize

        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (dynamicTableAddr == 0 and addr < classNameAddr) or \
           (dynamicTableAddr != 0 and addr < dynamicTableAddr):
            numOfEntries = Word(addr)
            MakeWord(addr)
            addr += 2

            for i in range(numOfEntries):
                MakeCustomWord(addr, self.__processorWordSize)
                MakeByte(addr + self.__processorWordSize)
                idc.make_array(addr + self.__processorWordSize, 4)

                recordAddr = GetCustomWord(addr, self.__processorWordSize)
                self.__CreateFunctionRecord(recordAddr)
                addr += 4 + self.__processorWordSize

    def __CreateFunctionRecord(self, addr: int) -> None:
        recordSize = Word(addr)
        funcNameAddr = addr + 2

        MakeWord(addr)

        nameAddr = GetCustomWord(funcNameAddr, self.__processorWordSize)
        name = ida_name.get_name(nameAddr)
        if self.__tableName not in name:
            MakeFunction(GetCustomWord(funcNameAddr, self.__processorWordSize))

        MakeCustomWord(funcNameAddr, self.__processorWordSize)
        MakeStr_PASCAL(funcNameAddr + self.__processorWordSize)
        funcBaseName = GetStr_PASCAL(funcNameAddr + self.__processorWordSize)
        MakeName(addr, "_" + self.__tableName + "_" + funcBaseName)

        funcPrototype = ("void __usercall "
                         + self.__tableName
                         + "_"
                         + funcBaseName
                         + "(")

        size = (3 + self.__processorWordSize
                + Byte(funcNameAddr + self.__processorWordSize))

        if recordSize > size:
            addr += size
            MakeCustomWord(addr, self.__processorWordSize)
            addr += self.__processorWordSize
            MakeDword(addr)
            addr += 4
            MakeByte(addr)

            numOfParams = Byte(addr)
            addr += 1

            if funcBaseName == "Create":
                numOfParams += 1

            for i in range(numOfParams):
                regStr = str()

                if self.__processorWordSize == 4:
                    if i == 0:
                        regStr = "@<eax>"
                    elif i == 1:
                        regStr = "@<edx>"
                    elif i == 2:
                        regStr = "@<ecx>"
                else:
                    if i == 0:
                        regStr = "@<rcx>"
                    elif i == 1:
                        regStr = "@<rdx>"
                    elif i == 2:
                        regStr = "@<r8>"
                    elif i == 3:
                        regStr = "@<r9>"

                if i == 1 and funcBaseName == "Create":
                    funcPrototype += "void* ShortInt_Alloc" + regStr
                else:
                    MakeByte(addr)
                    MakeCustomWord(addr + 1, self.__processorWordSize)
                    MakeWord(addr + 1 + self.__processorWordSize)
                    MakeStr_PASCAL(addr + 3 + self.__processorWordSize)

                    wordAddr = (addr + 4
                                + self.__processorWordSize
                                + Byte(addr + 3 + self.__processorWordSize))
                    MakeWord(wordAddr)

                    argTypeInfo = GetCustomWord(
                        addr + 1,
                        self.__processorWordSize
                    )

                    if argTypeInfo == 0:
                        typeName = "NoType"
                    elif ida_bytes.is_mapped(argTypeInfo) and ida_bytes.is_loaded(argTypeInfo):
                        typeInfoAddr = argTypeInfo + self.__processorWordSize
                        typeInfo = TypeInfo(typeInfoAddr)
                        typeInfo.MakeTable(1)
                        typeName = typeInfo.GetTypeName()
                    else:
                        return

                    paramNameAddr = addr + 3 + self.__processorWordSize
                    paramName = GetStr_PASCAL(paramNameAddr)
                    if paramName is None:
                        paramName = "RetVal"

                    funcPrototype += ("void* "
                                      + typeName
                                      + "_"
                                      + paramName
                                      + regStr)

                    addr = (addr + 6
                            + self.__processorWordSize
                            + Byte(addr + 3 + self.__processorWordSize))

                if i != numOfParams - 1:
                    funcPrototype += ", "

            MakeWord(addr)

        funcPrototype += ");"

        nameAddr = GetCustomWord(funcNameAddr, self.__processorWordSize)
        name = ida_name.get_name(nameAddr)

        if self.__tableName not in name:
            MakeName(
                GetCustomWord(funcNameAddr, self.__processorWordSize),
                self.__tableName + "_" + funcBaseName
            )

        idc.SetType(
            GetCustomWord(funcNameAddr, self.__processorWordSize),
            funcPrototype
        )

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(self.__tableAddr, ida_bytes.DELIT_DELNAMES, 2)

        addr = self.__tableAddr + 2
        numOfEntries = Word(self.__tableAddr)

        for i in range(numOfEntries):
            recordSize = Word(addr)
            ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, recordSize)
            addr = addr + recordSize

        dynamicTableAddr = self.__classInfo["Address"]["DynamicTable"]
        classNameAddr = self.__classInfo["Address"]["ClassName"]

        if (dynamicTableAddr == 0 and addr < classNameAddr) or \
           (dynamicTableAddr != 0 and addr < dynamicTableAddr):
            numOfEntries = Word(addr)
            ida_bytes.del_items(addr, ida_bytes.DELIT_DELNAMES, 2)
            addr += 2

            for i in range(numOfEntries):
                ida_bytes.del_items(
                    addr,
                    ida_bytes.DELIT_DELNAMES,
                    4 + self.__processorWordSize
                )
                ida_bytes.del_items(
                    GetCustomWord(addr, self.__processorWordSize),
                    ida_bytes.DELIT_DELNAMES,
                    Word(GetCustomWord(addr, self.__processorWordSize))
                )
                addr += 4 + self.__processorWordSize
