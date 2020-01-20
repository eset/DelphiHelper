#
# This module allows to parse Delphi's DynamicTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
from DelphiHelper.util.ida import *


class DynamicTable(object):

    def __init__(
            self,
            classInfo: dict[str, str | dict[str, int]]) -> None:
        self.__tableAddr = classInfo["Address"]["DynamicTable"]
        self.__tableName = classInfo["Name"]
        self.__processorWordSize = GetProcessorWordSize()

        if self.__tableAddr != 0:
            self.__numOfEntries = Word(self.__tableAddr)

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()

    def __CreateTable(self) -> None:
        MakeWord(self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_DynamicTable")

        for i in range(self.__numOfEntries):
            MakeWord(self.__tableAddr + 2 + 2 * i)

        for i in range(self.__numOfEntries):
            addr = (self.__tableAddr
                    + 2
                    + 2 * self.__numOfEntries
                    + self.__processorWordSize * i)
            MakeCustomWord(addr, self.__processorWordSize)

        ida_bytes.set_cmt(
            self.__tableAddr,
            "Count",
            0
        )
        ida_bytes.set_cmt(
            self.__tableAddr + 2,
            "Method/Message handler number",
            0
        )
        ida_bytes.set_cmt(
            self.__tableAddr + 2 + 2 * self.__numOfEntries,
            "Method/Message handler pointer",
            0
        )

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            self.__numOfEntries * (2 + self.__processorWordSize) + 2
        )
