#
# This module allows to parse and extract data from Delphi's VMTTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
from DelphiHelper.core.FuncStruct import FuncStruct
from DelphiHelper.util.delphi import DemangleFuncName
from DelphiHelper.util.ida import *


class VMTTable(object):

    def __init__(
            self,
            classInfo: dict[str, str | dict[str, int]],
            funcStruct: FuncStruct) -> None:
        self.__tableAddr = classInfo["Address"]["VMTTable"]
        self.__tableName = classInfo["Name"]
        self.__funcStruct = funcStruct
        self.__processorWordSize = GetProcessorWordSize()

        if classInfo["Address"]["InitTable"] != 0:
            self.__tableEndAddr = classInfo["Address"]["InitTable"]
        elif classInfo["Address"]["FieldTable"] != 0:
            self.__tableEndAddr = classInfo["Address"]["FieldTable"]
        elif classInfo["Address"]["MethodTable"] != 0:
            self.__tableEndAddr = classInfo["Address"]["MethodTable"]
        elif classInfo["Address"]["DynamicTable"] != 0:
            self.__tableEndAddr = classInfo["Address"]["DynamicTable"]
        elif classInfo["Address"]["ClassName"] != 0:
            self.__tableEndAddr = classInfo["Address"]["ClassName"]
        else:
            self.__tableEndAddr = self.__tableAddr

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTableAndExtractData()

    def __CreateTableAndExtractData(self) -> None:
        MakeName(self.__tableAddr, self.__tableName + "_VMT")

        offset = 0
        while self.__tableAddr + offset < self.__tableEndAddr:
            funcAddr = GetCustomWord(
                self.__tableAddr + offset,
                self.__processorWordSize
            )

            MakeFunction(funcAddr)
            DemangleFuncName(funcAddr)
            MakeCustomWord(self.__tableAddr + offset, self.__processorWordSize)

            ida_bytes.set_cmt(
                self.__tableAddr + offset,
                "'+" + ("%x" % offset).upper() + "'",
                0
            )

            self.__funcStruct.AddMember(funcAddr, offset)

            offset += self.__processorWordSize

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            self.__tableEndAddr - self.__tableAddr
        )
