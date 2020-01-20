#
# This module allows to parse Delphi's ClassTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_name
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


class ClassTable(object):

    def __init__(self, addr: int, tableName: str) -> None:
        self.__tableAddr = addr
        self.__tableName = tableName
        self.__tableEntries = list()
        self.__processorWordSize = GetProcessorWordSize()

        if self.__tableAddr != 0:
            self.__numOfEntries = Word(self.__tableAddr)

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()

        return self.__tableEntries

    def __CreateTable(self) -> None:
        MakeWord(self.__tableAddr)
        MakeName(self.__tableAddr, self.__tableName + "_ClassTable")
        ida_bytes.set_cmt(self.__tableAddr, "Number of entries", 0)

        addr = self.__tableAddr + 2

        for i in range(self.__numOfEntries):
            vmtStructAddr = GetCustomWord(addr, self.__processorWordSize)
            self.__tableEntries.append(vmtStructAddr)

            if ida_bytes.is_loaded(vmtStructAddr) and \
               vmtStructAddr != 0 and \
               ida_name.get_name(vmtStructAddr)[:4] != "VMT_":
                from DelphiHelper.core.DelphiClass import DelphiClass
                try:
                    DelphiClass(vmtStructAddr).MakeClass()
                except DelphiHelperError as e:
                    e.print()

            MakeCustomWord(addr, self.__processorWordSize)
            addr += self.__processorWordSize

    def __DeleteTable(self) -> None:
        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            self.__numOfEntries * self.__processorWordSize + 2
        )
