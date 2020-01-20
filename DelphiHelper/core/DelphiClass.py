#
# This module implements class for storing data extracted from Delphi's VMT
# structure
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_idaapi
import ida_name
from DelphiHelper.core.DelphiClass_DynamicTable import *
from DelphiHelper.core.DelphiClass_FieldTable import *
from DelphiHelper.core.DelphiClass_InitTable import *
from DelphiHelper.core.DelphiClass_IntfTable import *
from DelphiHelper.core.DelphiClass_MethodTable import *
from DelphiHelper.core.DelphiClass_TypeInfo import *
from DelphiHelper.core.DelphiClass_VMTTable import *
from DelphiHelper.core.FieldEnum import *
from DelphiHelper.core.FuncStruct import *
from DelphiHelper.util.delphi import DemangleFuncName
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


class DelphiClass(object):
    __CLASS_DESCRIPTION = [
        "SelfPtr",
        "IntfTable",
        "AutoTable",
        "InitTable",
        "TypeInfo",
        "FieldTable",
        "MethodTable",
        "DynamicTable",
        "ClassName",
        "InstanceSize",
        "Parent"
    ]

    def __init__(
            self,
            VMT_addr: int,
            className: str = str()) -> None:
        self.__processorWordSize = GetProcessorWordSize()

        if VMT_addr == 0:
            self.__VMTaddr = self.__GetVMTAddrByName(className)
        else:
            self.__VMTaddr = VMT_addr

        if self.IsDelphiClass():
            self.__classInfo = self.GetClassInfo()

            self.__fieldEnum = FieldEnum(
                self.__classInfo["Name"],
                self.__classInfo["FullName"]
            )

            self.__funcStruct = FuncStruct(
                self.__classInfo["Name"],
                self.__classInfo["FullName"]
            )

            self.__intfTable = IntfTable(self.__classInfo)
            self.__initTable = InitTable(self.__classInfo, self.__fieldEnum)

            self.__typeInfo = TypeInfo(
                self.__classInfo["Address"]["TypeInfo"],
                self.__fieldEnum
            )

            self.__fieldTable = FieldTable(self.__classInfo, self.__fieldEnum)
            self.__methodTable = MethodTable(self.__classInfo)
            self.__dynamicTable = DynamicTable(self.__classInfo)
            self.__VMTTable = VMTTable(self.__classInfo, self.__funcStruct)
        else:
            raise DelphiHelperError("Invalid VMT structure address: " + hex(self.__VMTaddr))

    def GetClassInfo(self) -> dict[str, str | dict[str, int]]:
        classInfo = {}
        classInfo["Address"] = self.__GetAddressTable()
        classInfo["Name"] = self.__GetClassName()
        classInfo["FullName"] = self.__GetVMTClassName()
        return classInfo

    def GetVMTAddress(self) -> int:
        return self.__VMTaddr

    def GetClassName(self) -> str:
        return self.__classInfo["Name"]

    def GetClassFullName(self) -> str:
        return self.__classInfo["FullName"]

    def GetClassAddress(self) -> int:
        return self.__classInfo["Address"]["Class"]

    def GetMethods(self) -> list[tuple[str, int]]:
        return self.__methodTable.GetMethods()

    def MakeClass(self) -> None:
        print(f"[INFO] Processing {self.__classInfo['FullName']}")

        self.__DeleteClassHeader()
        self.__MakeClassName()

        self.__ResolveParent(self.__classInfo["Address"]["ParentClass"])

        self.__intfTable.MakeTable()
        self.__initTable.MakeTable()
        self.__typeInfo.MakeTable()
        self.__fieldTable.MakeTable()
        self.__methodTable.MakeTable()
        self.__dynamicTable.MakeTable()
        self.__VMTTable.MakeTable()

        self.__MakeClassHeader()

    def IsDelphiClass(self) -> bool:
        if not ida_bytes.is_loaded(self.__VMTaddr) or \
           self.__VMTaddr == ida_idaapi.BADADDR or \
           self.__VMTaddr == 0:
            return False

        vmtTableAddr = GetCustomWord(self.__VMTaddr, self.__processorWordSize)

        if vmtTableAddr == 0 or vmtTableAddr < self.__VMTaddr:
            return False

        offset = vmtTableAddr - self.__VMTaddr

        if offset % self.__processorWordSize != 0 or \
           offset / self.__processorWordSize > 30 or \
           offset / self.__processorWordSize < 5:
            return False

        return True

    def __GetVMTClassName(self) -> str:
        return ("VMT_"
                + ("%x" % self.__VMTaddr).upper()
                + "_"
                + self.__GetClassName())

    def __GetClassName(self) -> str:
        return FixName(GetStr_PASCAL(self.__GetClassNameAddr()))

    def __GetClassNameAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 8 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetIntfTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 1 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetAutoTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 2 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetInitTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 3 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetTypeInfoAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 4 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetFieldTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 5 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetMethodTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 6 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetDynamicTableAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 7 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetParentClassAddr(self) -> int:
        return GetCustomWord(
            self.__VMTaddr + 10 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetAddressTable(self) -> dict[str, int]:
        addressTable = {}
        addressTable["Class"] = self.__VMTaddr
        addressTable["VMTTable"] = GetCustomWord(
            self.__VMTaddr,
            self.__processorWordSize
        )
        addressTable["ParentClass"] = self.__GetParentClassAddr()
        addressTable["IntfTable"] = self.__GetIntfTableAddr()
        addressTable["AutoTable"] = self.__GetAutoTableAddr()
        addressTable["InitTable"] = self.__GetInitTableAddr()
        addressTable["TypeInfo"] = self.__GetTypeInfoAddr()
        addressTable["FieldTable"] = self.__GetFieldTableAddr()
        addressTable["MethodTable"] = self.__GetMethodTableAddr()
        addressTable["DynamicTable"] = self.__GetDynamicTableAddr()
        addressTable["ClassName"] = self.__GetClassNameAddr()
        return addressTable

    def __GetVMTAddrByName(self, className: str) -> int:
        stringToFind = " "

        if className == str():
            return 0

        for a in className:
            stringToFind += hex(ord(a))[2:] + " "

        stringToFind = "07 " + hex(len(className))[2:] + stringToFind

        addr = find_bytes(stringToFind)
        if addr != ida_idaapi.BADADDR:
            addr += 2 + len(className)
            addr = FindRef_Dword(
                GetCustomWord(addr, 4),
                GetCustomWord(addr, 4),
                ida_bytes.BIN_SEARCH_BACKWARD
            )

        return addr

    def __DeleteClassHeader(self) -> None:
        ida_bytes.del_items(
            self.__VMTaddr,
            ida_bytes.DELIT_DELNAMES,
            GetCustomWord(
                self.__VMTaddr,
                self.__processorWordSize
            ) - self.__VMTaddr
        )

    def __MakeClassHeader(self) -> None:
        addr = self.__VMTaddr
        endAddr = GetCustomWord(self.__VMTaddr, self.__processorWordSize)
        i = 0

        while addr < endAddr and i < 30:
            MakeCustomWord(addr, self.__processorWordSize)

            if addr < self.__VMTaddr + 11 * self.__processorWordSize:
                ida_bytes.set_cmt(addr, self.__CLASS_DESCRIPTION[i], 0)
            else:
                DemangleFuncName(GetCustomWord(addr, self.__processorWordSize))

            addr += self.__processorWordSize
            i += 1

    def __MakeClassName(self) -> None:
        classNameAddr = self.__GetClassNameAddr()
        classNameLen = Byte(classNameAddr)

        ida_bytes.del_items(
            classNameAddr,
            ida_bytes.DELIT_DELNAMES,
            classNameLen + 1
        )

        MakeStr_PASCAL(classNameAddr)
        MakeName(classNameAddr, self.__classInfo["Name"] + "_ClassName")
        MakeCustomWord(self.__VMTaddr, self.__processorWordSize)

        ida_name.set_name(
            self.__VMTaddr,
            self.__classInfo["FullName"],
            ida_name.SN_NOCHECK
        )

    def __ResolveParent(self, parentClassAddr: int) -> None:
        if ida_bytes.is_loaded(parentClassAddr) and \
           parentClassAddr != 0 and \
           not ida_name.get_name(parentClassAddr).startswith("VMT_"):
            try:
                DelphiClass(parentClassAddr).MakeClass()
            except DelphiHelperError as e:
                print(f"[ERROR] {e.msg}")
