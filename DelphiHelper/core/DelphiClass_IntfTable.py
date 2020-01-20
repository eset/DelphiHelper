#
# This module allows to parse Delphi's IntfTable
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.

import idc
import ida_bytes
from DelphiHelper.core.DelphiClass_TypeInfo import *
from DelphiHelper.util.ida import *


class IntfTable(object):

    def __init__(self, classInfo: dict[str, str | dict[str, int]]) -> None:
        self.__tableAddr = classInfo["Address"]["IntfTable"]
        self.__classAddr = classInfo["Address"]["Class"]
        self.__tableName = classInfo["Name"]
        self.__processorWordSize = GetProcessorWordSize()
        self.__minIntfAddr = 0

        if self.__tableAddr != 0:
            self.__intfCount = Dword(self.__tableAddr)
            self.__typeInfoAddr = (self.__tableAddr
                                   + self.__processorWordSize
                                   + self.__intfCount * (16 + 3 * self.__processorWordSize))

            addr = self.__tableAddr + self.__processorWordSize
            intfList = list()

            for i in range(self.__intfCount):
                if GetCustomWord(addr + 16, self.__processorWordSize) != 0:
                    intf = GetCustomWord(addr + 16, self.__processorWordSize)
                    intfList.append(intf)
                addr += 3 * self.__processorWordSize + 16

            self.__minIntfAddr = 0

            if len(intfList) != 0:
                self.__minIntfAddr = intfList[0]

                for intfAddr in intfList:
                    if intfAddr < self.__minIntfAddr:
                        self.__minIntfAddr = intfAddr

    def GetTableAddress(self) -> int:
        return self.__tableAddr

    def MakeTable(self) -> None:
        if self.__tableAddr != 0:
            self.__DeleteTable()
            self.__CreateTable()

    def __CreateTable(self) -> None:
        MakeCustomWord(self.__tableAddr, self.__processorWordSize)
        MakeName(self.__tableAddr, self.__tableName + "_IntfTable")
        ida_bytes.set_cmt(self.__tableAddr, "Count", 0)

        addr = self.__tableAddr + self.__processorWordSize
        for i in range(self.__intfCount):
            MakeDword(addr)
            idc.make_array(addr, 4)
            MakeName(addr, self.__tableName + "_Interface" + str(i))

            MakeCustomWord(
                addr + 16,
                self.__processorWordSize
            )

            MakeName(
                GetCustomWord(addr + 16, self.__processorWordSize),
                self.__tableName + "_Interface" + str(i) + "_VMT"
            )

            MakeCustomWord(
                addr + self.__processorWordSize + 16,
                self.__processorWordSize
            )

            MakeCustomWord(
                addr + 2 * self.__processorWordSize + 16,
                self.__processorWordSize
            )

            addr += 3 * self.__processorWordSize + 16

        addr = (self.__typeInfoAddr
                + self.__intfCount * self.__processorWordSize)

        if addr <= self.__classAddr:
            addr = self.__typeInfoAddr

            for i in range(self.__intfCount):
                MakeCustomWord(addr, self.__processorWordSize)

                typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
                if ida_bytes.is_loaded(typeInfoAddr) and \
                   typeInfoAddr != 0 and \
                   "_TypeInfo" not in idc.get_name(typeInfoAddr):
                    typeInfo = TypeInfo(typeInfoAddr + self.__processorWordSize)
                    typeInfo.MakeTable(1)

                addr += self.__processorWordSize

        if self.__minIntfAddr != 0:
            addr = self.__minIntfAddr

            while addr < self.__tableAddr:
                MakeFunction(GetCustomWord(addr, self.__processorWordSize))
                MakeCustomWord(addr, self.__processorWordSize)
                addr += self.__processorWordSize

        if self.__intfCount != 0:
            ida_bytes.set_cmt(
                self.__tableAddr + self.__processorWordSize,
                "GUID",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + self.__processorWordSize + 16,
                "Interface VMT",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 2 * self.__processorWordSize + 16,
                "Interface's hidden field offset",
                0
            )
            ida_bytes.set_cmt(
                self.__tableAddr + 3 * self.__processorWordSize + 16,
                "Property implementing interface",
                0
            )

    def __DeleteTable(self) -> None:
        nbytes = ((3 * self.__processorWordSize + 16) * self.__intfCount
                  + self.__processorWordSize)

        ida_bytes.del_items(
            self.__tableAddr,
            ida_bytes.DELIT_DELNAMES,
            nbytes
        )

        addr = (self.__typeInfoAddr
                + self.__intfCount * self.__processorWordSize)

        if addr <= self.__classAddr:
            ida_bytes.del_items(
                self.__typeInfoAddr,
                ida_bytes.DELIT_DELNAMES,
                self.__processorWordSize * self.__intfCount
            )

        offset = self.__minIntfAddr - self.__tableAddr

        if self.__minIntfAddr != 0 and \
           offset % self.__processorWordSize == 0:
            ida_bytes.del_items(
                self.__minIntfAddr,
                ida_bytes.DELIT_DELNAMES,
                self.__tableAddr - self.__minIntfAddr
            )
