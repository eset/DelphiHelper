#
# This module allows to search for, parse and extract data from Delphi's DFM
# resource
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_bytes
import ida_kernwin
import ida_name
from DelphiHelper.core.DFMFinder import *
from DelphiHelper.core.DelphiClass import *
from DelphiHelper.core.DelphiForm import *
from DelphiHelper.util.exception import DelphiHelperError


def ParseDFMs() -> list[tuple[DelphiObject, list[tuple[str, int]], int]]:
    dfmList = DFMFinder().GetDFMList()
    numOfDfms = len(dfmList)
    delphiFormList = list()

    ida_kernwin.show_wait_box("NODELAY\nHIDECANCEL\nProcessing Delphi file's DFMs...")

    try:
        for i, dfmEntry in enumerate(dfmList):
            msg = "HIDECANCEL\nProcessing Delphi file's DFMs (%d/%d)" \
                % (i + 1, numOfDfms)
            ida_kernwin.replace_wait_box(msg)

            data = ida_bytes.get_bytes(dfmEntry[0], dfmEntry[1])

            if data and (ida_bytes.is_loaded(dfmEntry[0] + dfmEntry[1] - 1) or dfmEntry[1] == 10000000):
                dfmEntryParser = DFMParser(data, dfmEntry[1])

                if dfmEntryParser.CheckSignature():
                    methodList = list()
                    VMTAddr = 0
                    delphiDFM = dfmEntryParser.ParseForm()

                    try:
                        delphiRTTI = DelphiClass(0, delphiDFM.GetClassName())

                        VMTAddr = delphiRTTI.GetVMTAddress()
                        if not ida_name.get_name(VMTAddr).startswith("VMT_"):
                            delphiRTTI.MakeClass()

                        methodList = delphiRTTI.GetMethods()
                    except DelphiHelperError:
                        print(f"[WARNING] RTTI Class {delphiDFM.GetClassName()} not found!")

                    delphiFormList.append((delphiDFM, methodList, VMTAddr))

                del dfmEntryParser

        return delphiFormList
    finally:
        ida_kernwin.hide_wait_box()


class DFMParser(object):

    def __init__(self, data: bytes, dataSize: int) -> None:
        self.__resData = data
        self.__resDataSize = dataSize
        self.__resDataPos = 0

    def ParseForm(self) -> DelphiObject | None:
        if self.__ReadSignature():
            delphiForm = self.__ParseObject()
            return delphiForm
        return None

    def CheckSignature(self) -> bool:
        if self.__resDataSize < 4:
            return False
        return self.__resData.startswith(b"TPF0")

    def __ParseProperty(
            self,
            parentDelphiObj: DelphiObject) -> DelphiProperty | None:
        try:
            if self.__ReadRawData(1, 0)[0] == 0:
                self.__ReadByte()
                return None
        except DelphiHelperError:
            return None

        propName = self.__ReadString().decode()
        propType = self.__ReadByte()

        if propName is None or propType is None:
            return None

        propValue = self.__ReadPropertyValue(propType)

        delphiProp = DelphiProperty(
            propName,
            propType,
            propValue,
            parentDelphiObj
        )
        parentDelphiObj.AddProperty(delphiProp)

        return delphiProp

    def __ParseObject(
            self,
            parentDelphiObj: DelphiObject | None = None
            ) -> DelphiObject | None:
        try:
            if self.__ReadRawData(1, 0)[0] == 0:
                self.__ReadByte()
                return None
        except DelphiHelperError:
            return None

        if not self.__ReadPrefix():
            className = self.__ReadString().decode()
            objectName = self.__ReadString().decode()

            if className is not None and objectName is not None:
                childDelphiObj = DelphiObject(
                    className,
                    objectName,
                    parentDelphiObj
                )

                while self.__ParseProperty(childDelphiObj) is not None:
                    pass
                while self.__ParseObject(childDelphiObj) is not None:
                    pass

                if parentDelphiObj is not None:
                    parentDelphiObj.AddChildObject(childDelphiObj)

                return childDelphiObj
            else:
                raise DelphiHelperError("ClassName or ObjName is None")

    def __ReadSignature(self) -> bool:
        return self.__ReadRawData(4) == b"TPF0"

    def __OutOfDataCheck(self, size: int) -> bool:
        if self.__resDataPos + size - 1 >= self.__resDataSize:
            raise DelphiHelperError("DMF corrupted: No more data to read!")
        return False

    def __ReadRawData(self, size: int, shift: int = 1) -> bytes:
        if size < 0:
            size = 0

        self.__OutOfDataCheck(size)
        rawData = self.__resData[self.__resDataPos:self.__resDataPos+size]

        if shift == 1:
            self.__resDataPos += size

        return rawData

    def __ReadByte(self) -> int:
        return self.__ReadRawData(1)[0]

    def __ReadWord(self) -> int:
        rawData = self.__ReadRawData(2)
        value = 0

        for i in range(2):
            value += (rawData[i] << i*8)
        return value

    def __ReadDword(self) -> int:
        rawData = self.__ReadRawData(4)
        value = 0

        for i in range(4):
            value += (rawData[i] << i*8)
        return value

    def __ReadString(self) -> bytes:
        return self.__ReadRawData(self.__ReadByte())

    def __ReadLString(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword())

    def __ReadWString(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword() * 2)

    def __ReadData(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword())

    def __ReadSingle(self) -> bytes:
        return self.__ReadRawData(4)

    def __ReadExtended(self) -> bytes:
        return self.__ReadRawData(10)

    def __ReadDouble(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadCurrency(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadDate(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadInt64(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadList(self) -> list:
        listElementType = self.__ReadByte()
        listElements = list()

        while listElementType != 0:
            listElements.append(
                (self.__ReadPropertyValue(listElementType), listElementType)
            )
            listElementType = self.__ReadByte()
        return listElements

    def __ReadSet(self) -> list:
        setElements = list()

        while True:
            elem = self.__ReadString()

            if len(elem) != 0:
                setElements.append(elem)
            else:
                break

        return setElements

    def __ReadCollection(self) -> list:
        collectionElements = list()

        while True:
            elementValue = None
            elementType = self.__ReadByte()

            if elementType == 0:
                break
            elif elementType == 2 or elementType == 3 or elementType == 4:
                elementValue = self.__ReadPropertyValue(elementType)
            elif elementType == 1:
                attrList = list()
                flag = True

                while flag:
                    attrName = self.__ReadString().decode()

                    if len(attrName) == 0:
                        flag = False
                    else:
                        attrType = self.__ReadByte()
                        attrList.append((
                            attrName,
                            self.__ReadPropertyValue(attrType),
                            attrType
                        ))
            else:
                raise DelphiHelperError("Invalid collection format!")

            collectionElements.append((elementValue, attrList))

        return collectionElements

    def __ReadPrefix(self) -> bool:
        if self.__ReadRawData(1, 0)[0] & 0xf0 == 0xf0:
            prefix = self.__ReadByte()

            flags = prefix & 0x0f

            if flags > 7:
                raise DelphiHelperError("Unsupported DFM Prefix.")

            if (flags & 2) != 0:
                propType = self.__ReadByte()

                if propType == 2 or propType == 3 or propType == 4:
                    self.__ReadPropertyValue(propType)
                else:
                    raise DelphiHelperError("Unsupported DFM Prefix.")

        return False

    def __ReadPropertyValue(
            self,
            propType: int) -> bytes | int | list | str:
        match propType:
            # Null
            case 0: return "Null"
            # List
            case 1: return self.__ReadList()
            # Int8
            case 2: return self.__ReadByte()
            # Int16
            case 3: return self.__ReadWord()
            # Int32
            case 4: return self.__ReadDword()
            # Extended
            case 5: return self.__ReadExtended()
            # String
            case 6: return self.__ReadString()
            # Ident
            case 7: return self.__ReadString()
            # False
            case 8: return 0
            # True
            case 9: return 1
            # Binary
            case 10: return self.__ReadData()
            # Set
            case 11: return self.__ReadSet()
            # LString
            case 12: return self.__ReadLString()
            # Nil
            case 13: return "Nil"
            # Collection
            case 14: return self.__ReadCollection()
            # Single
            case 15: return self.__ReadSingle()
            # Currency
            case 16: return self.__ReadCurrency()
            # Date
            case 17: return self.__ReadDate()
            # WString
            case 18: return self.__ReadWString()
            # Int64
            case 19: return self.__ReadInt64()
            # UTF8String
            case 20: return self.__ReadLString()
            # Double
            case 21: return self.__ReadDouble()
            case _:
                raise DelphiHelperError("Unsupported property type: " + str(propType))
