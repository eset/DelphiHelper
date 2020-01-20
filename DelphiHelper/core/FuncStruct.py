#
# This module allows to store data extracted from Delphi's RTTI tables into
# IDA's structures
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_idaapi
import ida_name
import idc
from DelphiHelper.util.ida import GetProcessorWordSize


class FuncStruct(object):

    def __init__(self, funcStructName: str, funcStructComment: str) -> None:
        self.__funcStructName = funcStructName
        self.__funcStructComment = funcStructComment
        self.__funcStructId = ida_idaapi.BADADDR
        self.__processorWordSize = GetProcessorWordSize()

    def AddMember(self, funcAddr: int, funcOffset: int) -> None:
        self.__CreateFuncStruct()
        self.__AddFuncStructMember(funcAddr, funcOffset)

    def __CreateFuncStruct(self) -> None:
        if self.__funcStructId == ida_idaapi.BADADDR:
            self.__DeleteStruct()
            self.__funcStructId = idc.add_struc(-1, self.__funcStructName, 0)

            idc.set_struc_cmt(
                self.__funcStructId,
                self.__funcStructComment,
                0
            )

    def __AddFuncStructMember(self, funcAddr: int, funcOffset: int) -> None:
        funcName = ida_name.get_name(funcAddr)

        if self.__processorWordSize == 4:
            idc.add_struc_member(
                self.__funcStructId,
                funcName + "_" + hex(funcOffset),
                funcOffset,
                ida_bytes.FF_DWORD,
                -1,
                4
            )
        else:
            idc.add_struc_member(
                self.__funcStructId,
                funcName + "_" + hex(funcOffset),
                funcOffset,
                ida_bytes.FF_QWORD,
                -1,
                8
            )

        memberId = idc.get_member_id(self.__funcStructId, funcOffset)

        idc.set_member_cmt(
            self.__funcStructId,
            funcOffset,
            "0x" + ("%x" % funcAddr),
            1
        )

        structMemberPrototype = self.__GetStructMemberPrototype(funcName)
        if structMemberPrototype is not None:
            idc.SetType(memberId, structMemberPrototype)

    def __GetStructMemberPrototype(self, funcName: str) -> str | None:
        structMemberPrototype = idc.get_type(idc.get_name_ea_simple(funcName))

        if structMemberPrototype is not None:
            funcNameStart = structMemberPrototype.find("(")

            if funcNameStart != -1 and \
               structMemberPrototype[funcNameStart - 1] != " ":
                structMemberPrototype = (structMemberPrototype[0: funcNameStart]
                                         + "(*"
                                         + funcName
                                         + ")"
                                         + structMemberPrototype[funcNameStart:])

        return structMemberPrototype

    def __DeleteStruct(self) -> None:
        structId = idc.get_struc_id(self.__funcStructName)

        if structId != ida_idaapi.BADADDR:
            idc.del_struc(structId)

        self.__funcStructId = ida_idaapi.BADADDR
