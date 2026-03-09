#
# This module allows to create IDA structure storing data extracted from VMT
# and Field table
#
# Copyright (c) 2025-2026 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_idaapi
import ida_name
import idautils
import idc

from DelphiHelper.util.ida import (
    FixName,
    GetCustomWord,
    GetProcessorWordSize,
    GetStructComment,
    GetStructMemberComment,
)


class ClassStruct(object):

    def __init__(self, classStructName: str, classStructComment: str) -> None:
        self.__classStructName = classStructName + "_Self"
        self.__classStructComment = classStructComment
        self.__classStructId = ida_idaapi.BADADDR
        self.__processorWordSize = GetProcessorWordSize()

    def Create(self) -> None:
        self.__CreateClassStruct()

    def AddMember(
            self,
            memberType: str,
            memberName: str,
            memberOffset: int) -> None:
        self.__CreateClassStruct()
        self.__AddClassStructMember(memberType, memberName, memberOffset)

    def __CreateClassStruct(self) -> None:
        if self.__classStructId == ida_idaapi.BADADDR:
            self.__DeleteStruct()

            self.__classStructId = idc.add_struc(
                -1,
                self.__classStructName,
                0
            )

            idc.set_struc_cmt(
                self.__classStructId,
                self.__classStructComment,
                0
            )

            idc.add_struc_member(
                self.__classStructId,
                self.__classStructName[:-5] + "_VMT",
                0,
                ida_bytes.FF_DWORD,
                -1,
                4
            )

    def __AddClassStructMember(
            self,
            memberType: str,
            memberName: str,
            memberOffset: int) -> None:
        structMemberName = (memberType
                            + "_"
                            + memberName)
        structMemberName = FixName(structMemberName)

        name = idc.get_member_name(self.__classStructId, memberOffset)
        if name is not None and not name.startswith("gap"):
            if name == structMemberName:
                return
            else:
                idc.set_member_name(
                    self.__classStructId,
                    memberOffset,
                    structMemberName
                )
                return

        idc.add_struc_member(
            self.__classStructId,
            structMemberName,
            memberOffset,
            ida_bytes.FF_BYTE,
            -1,
            1
        )

        idc.set_member_cmt(
            self.__classStructId,
            memberOffset,
            FixName(memberType),
            0
        )

    def __DeleteStruct(self) -> None:
        structId = idc.get_struc_id(self.__classStructName)

        if structId != ida_idaapi.BADADDR:
            idc.del_struc(structId)

        self.__classStructId = ida_idaapi.BADADDR


def UpdateClassStructures() -> None:
    visited = set()  # Track processed structures to prevent infinite recursion

    for struct in idautils.Structs():
        structID = struct[1]
        structName = struct[2]
        structCmt = GetStructComment(structID)

        if structName.endswith("_Self") and \
           idc.get_type(idc.get_member_id(structID, 0)) == "int" and \
           structCmt is not None and \
           structCmt.startswith("VMT_"):
            propagateBaseClassFields(structID, structName, visited)

    for struct in idautils.Structs():
        if struct[2].endswith("_Self"):
            fixMemberTypes(struct[1])


def fixMemberTypes(structID: int) -> None:
    for member in idautils.StructMembers(structID):
        if member[0] != 0 and not member[1].startswith("gap"):
            memberCmt = GetStructMemberComment(structID, member[0])
            if memberCmt is not None and \
               memberCmt[0] == 'T' and \
               idc.get_struc_id(memberCmt + "_Self") != ida_idaapi.BADADDR:
                memberID = idc.get_member_id(structID, member[0])
                idc.SetType(memberID, memberCmt + "_Self*")


def propagateBaseClassFields(structID: int, structName: str, visited: set) -> None:
    # Prevent infinite recursion from circular inheritance
    if structID in visited:
        return
    visited.add(structID)

    processorWordSize = GetProcessorWordSize()
    memberID = idc.get_member_id(structID, 0)

    structCmt = GetStructComment(structID)
    if structCmt is None:
        return

    classAddr = idc.get_name_ea_simple(structCmt)
    parentClassAddr = GetCustomWord(
        classAddr + 10 * processorWordSize,
        processorWordSize
    )

    if parentClassAddr == 0 or not ida_bytes.is_loaded(parentClassAddr):
        idc.SetType(memberID, "void*")
        return

    if ida_name.get_name(parentClassAddr).startswith("VMT_"):
        parentClassName = ida_name.get_name(parentClassAddr).split('_', 2)[2]
        parentStructName = parentClassName + "_Self"
        parentStructID = idc.get_struc_id(parentStructName)

        if parentStructID != ida_idaapi.BADADDR:
            if idc.get_type(idc.get_member_id(parentStructID, 0)) == "int":
                propagateBaseClassFields(parentStructID, parentStructName, visited)

            for member in idautils.StructMembers(parentStructID):
                if member[0] != 0 and not member[1].startswith("gap"):
                    idc.add_struc_member(
                        structID,
                        member[1],
                        member[0],
                        ida_bytes.FF_BYTE,
                        -1,
                        1
                    )

                    idc.set_member_cmt(
                        structID,
                        member[0],
                        GetStructMemberComment(parentStructID, member[0]),
                        0
                    )

        memberName = idc.get_member_name(structID, 0)

        if idc.get_struc_id(memberName) == ida_idaapi.BADADDR:
            idc.SetType(memberID, "void*")
        else:
            idc.SetType(memberID, structName[:-5] + "_VMT*")
