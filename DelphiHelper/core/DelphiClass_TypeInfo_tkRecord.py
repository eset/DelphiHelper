#
# This module allows to parse and extract data from Delphi's TypeInfo tkRecord
#
# Copyright (c) 2020-2025 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_funcs
import idc
from DelphiHelper.util.delphi import GetParamRegister
from DelphiHelper.util.ida import *


class TypeInfo_tkRecord(object):

    def __init__(
            self,
            typeDataAddr: int,
            typeName: str,
            delphiVersion: int) -> None:
        self.__processorWordSize = GetProcessorWordSize()
        self.__typeDataAddr = typeDataAddr

        if len(typeName) == 0:
             self.__typeName = "Record_" + hex(self.__typeDataAddr)
        else:
            self.__typeName = typeName
        self.__delphiVersion = delphiVersion

    def CreateTypeData(self) -> None:
        addr = self.__typeDataAddr

        MakeDword(addr)
        ida_bytes.set_cmt(addr, "TypeData.Size", 0)
        addr += 4

        addr = self.__CreateManagedFields(addr)

        if self.__delphiVersion != -1 and self.__delphiVersion >= 2010:
            MakeByte(addr)
            ida_bytes.set_cmt(addr, "TypeData.NumOps", 0)
            numOps = Byte(addr)
            addr += 1

            if numOps:
                ida_bytes.set_cmt(addr, "TypeData.RecOps", 0)
                print("WARNING WARNING TypeData.RecOps")

                for i in range(numOps):
                    MakeCustomWord(addr, self.__processorWordSize)
                    addr += self.__processorWordSize

            addr = self.__CreateRecordTypeField(addr)

            MakeWord(addr)
            ida_bytes.set_cmt(addr, "TypeData.RecAttrData", 0)
            addr += Word(addr)

            if self.__delphiVersion >= 2012:
                addr = self.__CreateRecordTypeMethod(addr)

    def __CreateRecordTypeMethod(self, addr: int) -> int:
        MakeWord(addr)
        ida_bytes.set_cmt(addr, "TypeData.RecMethCnt", 0)
        recMethCnt = Word(addr)
        addr += 2

        if recMethCnt and recMethCnt <= 4096:
            ida_bytes.set_cmt(addr, "TypeData.RecMeths", 0)

            for i in range(recMethCnt):
                # Flags
                ida_bytes.set_cmt(addr, "TypeData.RecMeths.Flags", 0)
                MakeByte(addr)

                # Code
                MakeCustomWord(addr + 1, self.__processorWordSize)
                ida_bytes.set_cmt(addr + 1, "TypeData.RecMeths.Code", 0)
                funcAddr = GetCustomWord(addr + 1, self.__processorWordSize)

                # Name
                MakeStr_PASCAL(addr + 1 + self.__processorWordSize)
                nameSize = Byte(addr + 1 + self.__processorWordSize)
                funcName = GetStr_PASCAL(addr + 1 + self.__processorWordSize)
                ida_bytes.set_cmt(
                    addr + 1 + self.__processorWordSize,
                    "TypeData.RecMeths.Name",
                    0
                )

                if len(funcName) == 0:
                    funcName = hex(funcAddr)

                MakeName(addr, self.__typeName + "_RecMeth_" + funcName)

                addr += 2 + self.__processorWordSize + nameSize
                # ProcedureSignature
                # Flags
                MakeByte(addr)
                ida_bytes.set_cmt(
                    addr,
                    "TypeData.RecMeths.ProcedureSignature.Flags",
                    0
                )

                funcRetType = "NoType"
                funcParamList = list()

                if Byte(addr) != 0xFF:
                    # CC
                    MakeByte(addr + 1)
                    ida_bytes.set_cmt(
                        addr + 1,
                        "TypeData.RecMeths.ProcedureSignature.CC",
                        0
                    )

                    # ResultType
                    typeInfoAddr = GetCustomWord(
                        addr + 2,
                        self.__processorWordSize
                    )
                    MakeCustomWord(addr + 2, self.__processorWordSize)
                    ida_bytes.set_cmt(
                        addr + 2,
                        "TypeData.RecMeths.ProcedureSignature.ResultType",
                        0
                    )

                    if typeInfoAddr and \
                       ida_bytes.is_mapped(typeInfoAddr) and \
                       ida_bytes.is_loaded(typeInfoAddr):
                        from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
                        typeInfoAddr += self.__processorWordSize
                        typeInfo = TypeInfo(self.__delphiVersion, typeInfoAddr)
                        typeInfo.MakeTable(1)
                        funcRetType = typeInfo.GetTypeName()

                    # ParamCnt
                    MakeByte(addr + 2 + self.__processorWordSize)
                    paramCnt = Byte(addr + 2 + self.__processorWordSize)
                    ida_bytes.set_cmt(
                        addr + 2 + self.__processorWordSize,
                        "TypeData.RecMeths.ProcedureSignature.ParamCnt",
                        0
                    )

                    addr += 3 + self.__processorWordSize

                    # Params
                    for i in range(paramCnt):
                        addr, funcParam = self.__CreateProcedureParam(addr)
                        funcParamList.append(funcParam)
                else:
                    addr += 1

                # AttrData
                MakeWord(addr)
                ida_bytes.set_cmt(
                    addr,
                    "TypeData.RecMeths.ProcedureSignature.AttrData",
                    0
                )
                addr += Word(addr)

                self.__ProcessRecordMethod(
                    funcAddr,
                    funcName,
                    funcRetType,
                    funcParamList
                )

        return addr

    def __ProcessRecordMethod(
            self,
            funcAddr: int,
            funcName: str,
            funcRetType: str,
            funcParamList: list[(str, str)]) -> None:
        if funcAddr == 0 or \
           ida_name.get_name(funcAddr).startswith("sub_nullsub") or \
           ida_name.get_name(funcAddr).startswith(self.__typeName):
            return

        if Byte(funcAddr) == 0:
            MakeName(funcAddr, "sub_nullsub")
        else:
            MakeFunction(funcAddr)

            funcFullName = self.__typeName + "_" + funcName
            MakeName(funcAddr, funcFullName)

            if len(funcParamList):
                functionCmt = self.__typeName + "::" + funcName + "("
                for funcType, funcName in funcParamList:
                    functionCmt += funcType + " " + funcName + ","
                functionCmt = functionCmt[:-1] + ")"
            else:
                functionCmt = self.__typeName + "::" + funcName + "()"

            if funcRetType != "NoType":
                functionCmt += ":" + funcRetType

            ida_funcs.set_func_cmt(
                funcAddr,
                functionCmt,
                1
            )

            funcPrototype = "void __usercall " + FixName(funcFullName) + "("
            for i in range(len(funcParamList)):
                funcPrototype += ("void* "
                                  + funcParamList[i][0]
                                  + "_"
                                  + funcParamList[i][1]
                                  + GetParamRegister(i))

                if i != len(funcParamList) - 1:
                    funcPrototype += ", "

            funcPrototype += ");"

            idc.SetType(funcAddr, funcPrototype)

    def __CreateProcedureParam(self, addr: int) -> (int, (str, str)):
        # Flags
        MakeByte(addr)
        ida_bytes.set_cmt(
            addr,
            "TypeData.RecMeths.ProcedureSignature.ProcedureParam.Flags",
            0
        )

        # ParamType
        typeInfoAddr = GetCustomWord(addr + 1, self.__processorWordSize)
        MakeCustomWord(addr + 1, self.__processorWordSize)
        ida_bytes.set_cmt(
            addr + 1,
            "TypeData.RecMeths.ProcedureSignature.ProcedureParam.ParamType",
            0
        )

        paramType = "NoType"
        if typeInfoAddr and \
           ida_bytes.is_mapped(typeInfoAddr) and \
           ida_bytes.is_loaded(typeInfoAddr):
            from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
            typeInfoAddr += self.__processorWordSize
            typeInfo = TypeInfo(self.__delphiVersion, typeInfoAddr)
            typeInfo.MakeTable(1)
            paramType = typeInfo.GetTypeName()

        # Name
        MakeStr_PASCAL(addr + 1 + self.__processorWordSize)
        nameSize = Byte(addr + 1 + self.__processorWordSize)
        paramName = GetStr_PASCAL(addr + 1 + self.__processorWordSize)
        ida_bytes.set_cmt(
            addr + 1 + self.__processorWordSize,
            "TypeData.RecMeths.ProcedureSignature.ProcedureParam.Name",
            0
        )

        # AttrData
        MakeWord(addr + 2 + self.__processorWordSize + nameSize)
        ida_bytes.set_cmt(
            addr + 2 + self.__processorWordSize + nameSize,
            "TypeData.RecMeths.ProcedureSignature.ProcedureParam.AttrData",
            0
        )

        if len(paramName) == 0:
            paramName = "UnknownParam"

        return addr + 4 + self.__processorWordSize + nameSize, (paramType, paramName)

    def __CreateManagedFields(self, addr: int) -> int:
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "TypeData.ManagedFieldCount", 0)
        managedFieldCount = Dword(addr)
        addr += 4

        if managedFieldCount:
            ida_bytes.set_cmt(addr, "TypeData.ManagedFields", 0)

            for i in range(managedFieldCount):
                typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
                from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
                typeInfo = TypeInfo(self.__delphiVersion)
                typeInfo.ResolveTypeInfo(typeInfoAddr, True) 

                MakeCustomWord(addr, self.__processorWordSize)
                MakeCustomWord(
                    addr + self.__processorWordSize,
                    self.__processorWordSize
                )
                addr += 2 * self.__processorWordSize

        return addr

    def __CreateRecordTypeField(self, addr: int) -> int:
        MakeDword(addr)
        ida_bytes.set_cmt(addr, "TypeData.RecFldCnt", 0)
        recFldCnt = Dword(addr)
        addr += 4

        for i in range(recFldCnt):
            typeInfoAddr = GetCustomWord(addr, self.__processorWordSize)
            from DelphiHelper.core.DelphiClass_TypeInfo import TypeInfo
            typeInfo = TypeInfo(self.__delphiVersion)
            typeInfo.ResolveTypeInfo(typeInfoAddr, True)                

            # TypeRef
            MakeCustomWord(addr, self.__processorWordSize)
            ida_bytes.set_cmt(addr, "TypeData.RecField.TypeRef", 0)

            # FldOffset
            MakeCustomWord(
                addr + self.__processorWordSize,
                self.__processorWordSize
            )
            ida_bytes.set_cmt(
                addr + self.__processorWordSize,
                "TypeData.RecField.FldOffset",
                0
            )

            # Flags
            MakeByte(addr + 2 * self.__processorWordSize)
            ida_bytes.set_cmt(
                addr + 2 * self.__processorWordSize,
                "TypeData.RecField.Flags",
                0
            )

            # Name
            MakeStr_PASCAL(addr + 2 * self.__processorWordSize + 1)
            fieldName = GetStr_PASCAL(addr + 2 * self.__processorWordSize + 1)
            fieldNameSize = Byte(addr + 2 * self.__processorWordSize + 1)
            ida_bytes.set_cmt(
                addr + 2 * self.__processorWordSize + 1,
                "TypeData.RecField.Name",
                0
            )

            # AttrData
            MakeWord(addr + 2 * self.__processorWordSize + 2 + fieldNameSize)
            attrDataSize = Word(addr + 2 * self.__processorWordSize + 2 + fieldNameSize)
            ida_bytes.set_cmt(
                addr + 2 * self.__processorWordSize + 2 + fieldNameSize,
                "TypeData.RecField.AttrData",
                0
            )

            if len(fieldName) == 0:
                fieldName = hex(addr)

            MakeName(addr, self.__typeName + "_RecField_" + fieldName)
            addr += 2 * self.__processorWordSize + 2 + fieldNameSize + attrDataSize

        return addr

    def DeleteTypeData(self) -> None:
        managedFieldsSize = 0
        if Dword(self.__typeDataAddr + 4):
            managedFieldsSize = Dword(self.__typeDataAddr + 4) * 2 * self.__processorWordSize

        addr = self.__typeDataAddr + 8 + managedFieldsSize

        if self.__delphiVersion != -1 and self.__delphiVersion >= 2010:
            numOps = Byte(addr)
            addr += 1 + numOps * self.__processorWordSize + 4

            for i in range(Dword(addr - 4)):
                fieldNameSize = Byte(addr + 2 * self.__processorWordSize + 1)
                attrDataSize = Word(addr + 2 * self.__processorWordSize + 2 + fieldNameSize)
                addr += 2 * self.__processorWordSize + 2 + fieldNameSize + attrDataSize

            addr += Word(addr)

            if self.__delphiVersion >= 2012:
                recMethCnt = Word(addr)
                addr += 2

                if recMethCnt and recMethCnt <= 4096:
                    for i in range(recMethCnt):
                        addr += 1 + self.__processorWordSize
                        addr += 2 + Byte(addr)

                        if Byte(addr - 1) != 0xFF:
                            addr += 2 + self.__processorWordSize
                            for y in range(Byte(addr - 1)):
                                addr += 1 + self.__processorWordSize
                                addr += 3 + Byte(addr)
                        addr += Word(addr)

        ida_bytes.del_items(
            self.__typeDataAddr,
            ida_bytes.DELIT_DELNAMES,
            addr - self.__typeDataAddr
        )
