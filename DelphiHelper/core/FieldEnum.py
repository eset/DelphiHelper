#
# This module allows to store data from Delphi's FieldTable in IDA's enums
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import idc
import ida_idaapi
from DelphiHelper.util.ida import FixName


class FieldEnum(object):

    def __init__(self, enumName: str, enumComment: str) -> None:
        self.__fieldEnumName = enumName
        self.__fieldEnumComment = enumComment
        self.__fieldEnumId = ida_idaapi.BADADDR

    def AddMember(
            self,
            memberType: str,
            memberName: str,
            enumMemberValue: int) -> None:
        self.__CreateFieldEnum()
        self.__AddFieldEnumMember(
            memberType,
            memberName,
            enumMemberValue
        )

    def __CreateFieldEnum(self) -> None:
        if self.__fieldEnumId == ida_idaapi.BADADDR:
            self.__DeleteEnum()

            self.__fieldEnumId = idc.add_enum(
                ida_idaapi.BADADDR,
                self.__fieldEnumName + "_Fields",
                ida_bytes.hex_flag()
            )
            idc.set_enum_cmt(self.__fieldEnumId, self.__fieldEnumComment, 0)

    def __AddFieldEnumMember(
            self,
            memberType: str,
            memberName: str,
            enumMemberValue: int) -> None:
        enumMemberName = (self.__fieldEnumName
                          + "_"
                          + memberType
                          + "_"
                          + memberName)
        enumMemberName = FixName(enumMemberName)

        memberId = idc.get_enum_member_by_name(enumMemberName)

        if memberId == ida_idaapi.BADADDR:
            idc.add_enum_member(
                self.__fieldEnumId,
                enumMemberName,
                enumMemberValue,
                -1
            )
        elif idc.get_enum_member_value(memberId) != enumMemberValue:
            self.__AddFieldEnumMember(
                memberType,
                memberName + "_",
                enumMemberValue
            )

    def __DeleteEnum(self) -> None:
        fieldEnumId = idc.get_enum(self.__fieldEnumName + "_Fields")

        if fieldEnumId != ida_idaapi.BADADDR:
            idc.del_enum(fieldEnumId)

        self.__fieldEnumId = ida_idaapi.BADADDR
