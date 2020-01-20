#
# This module implements simple heuristic for searching for EP functions
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_idaapi
import ida_kernwin
import ida_name
import ida_ua
import idautils
import idc
from DelphiHelper.core.ClassResolver import *
from DelphiHelper.core.DelphiClass import *
from DelphiHelper.util.delphi import FindInitTable, GetApplicationClassAddr
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


class EPFinder(object):

    def FindEPFunction(self) -> None:
        createFormRef = dict()
        initExeRef = list()
        EPAddrToJmp = 0
        createFormFuncAddr = 0
        processorWordSize = GetProcessorWordSize()

        classAddr = GetApplicationClassAddr()

        if classAddr != ida_idaapi.BADADDR:
            ResolveApplicationClass(classAddr)
            # CreateForm
            createFormStrAddr = find_bytes("0A 43 72 65 61 74 65 46 6F 72 6D")

            if createFormStrAddr != ida_idaapi.BADADDR:
                createFormFuncAddr = GetCustomWord(
                    createFormStrAddr - processorWordSize,
                    processorWordSize
                )

        if createFormFuncAddr == 0:
            for funcAddr in idautils.Functions():
                funcName = ida_name.get_name(funcAddr)

                if "TApplication" in funcName and "CreateForm" in funcName:
                    createFormFuncAddr = funcAddr
                    break

        if createFormFuncAddr != 0:
            for ref in idautils.CodeRefsTo(createFormFuncAddr, 1):
                createFormRef[ref] = self.__getFormName(ref)

        initTable = FindInitTable()
        if initTable:
            for ref in idautils.DataRefsTo(initTable):
                initExeRef.append(ref)

        if initExeRef or createFormRef:
            i = 0
            print("[INFO] Found EP functions:")

            if initExeRef:
                EPAddrToJmp = initExeRef[0]

                for addr in initExeRef:
                    print(f"[INFO] EP{i}: 0x{addr:x} InitExe/InitLib")
                    i += 1

            if len(createFormRef):
                for addr, name in createFormRef.items():
                    if EPAddrToJmp == 0:
                        EPAddrToJmp = addr

                    if name == "":
                        print(f"[INFO] EP{i}: 0x{addr:x}")
                    else:
                        print(f"[INFO] EP{i}: 0x{addr:x} CreateForm(\"{name}\")")
                    i += 1

            if EPAddrToJmp != 0:
                ida_kernwin.jumpto(EPAddrToJmp)
        else:
            print("[INFO] EP function not found!")

    def __getFormName(self, createFormRef: int) -> str:
        addr = createFormRef
        regEdx = "edx"
        if Is64bit():
            regEdx = "rdx"

        counter = 3
        while counter != 0:
            addr = idc.prev_head(addr)
            if ida_ua.print_insn_mnem(addr) == "mov" and \
               idc.print_operand(addr, 0) == regEdx and \
               idc.get_operand_type(addr, 1) == 0x2:
                addr = idc.get_operand_value(addr, 1)
                try:
                    delphiClass = DelphiClass(addr)
                    if not ida_name.get_name(addr).startswith("VMT_"):
                        delphiClass.MakeClass()
                    return delphiClass.GetClassFullName()
                except DelphiHelperError:
                    return ""
            counter -= 1
        return ""
