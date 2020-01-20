#
# This module allows to parse IDR Knowledge base files and to determine
# Delphi's version.
#
# The module is based on code from IDR project
# (https://github.com/crypto2011/IDR),
# which is licensed under the MIT License.
#

"""
MIT License

Copyright (c) 2006-2018 crypto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import ida_idaapi
import ida_kernwin
import struct
from DelphiHelper.util.delphi import *
from DelphiHelper.util.exception import DelphiHelperError
from DelphiHelper.util.ida import *


class KBParser(object):

    def __init__(self, KB_filename: str) -> None:
        self.__moduleOffsets = list()
        self.__constOffsets = list()
        self.__typeOffsets = list()
        self.__varOffsets = list()
        self.__resStrOffsets = list()
        self.__procOffsets = list()

        self.__kbFile = open(KB_filename, "rb")

        if not self.__CheckKBFile():
            self.__kbFile.close()
            raise DelphiHelperError("Unexpected Knowledge base file format.")

        self.__kbFile.seek(-4, 2)
        sectionsOffset = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__kbFile.seek(sectionsOffset, 0)

        self.__moduleCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxModuleDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__moduleCount):
            self.__moduleOffsets.append(self.__ReadOffetsInfo())

        self.__constCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxConstDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__constCount):
            self.__constOffsets.append(self.__ReadOffetsInfo())

        self.__typeCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxTypeDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__typeCount):
            self.__typeOffsets.append(self.__ReadOffetsInfo())

        self.__varCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxVarDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__varCount):
            self.__varOffsets.append(self.__ReadOffetsInfo())

        self.__resStrCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxResStrDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__resStrCount):
            self.__resStrOffsets.append(self.__ReadOffetsInfo())

        self.__procCount = struct.unpack("i", self.__kbFile.read(4))[0]
        self.__maxProcDataSize = struct.unpack("i", self.__kbFile.read(4))[0]

        for i in range(self.__procCount):
            self.__procOffsets.append(self.__ReadOffetsInfo())

        self.__kbFile.seek(0, 0)
        self.__kbMem = bytes()
        self.__kbMem = self.__kbFile.read()
        self.__kbFile.close()

    def __ReadOffetsInfo(self) -> list:
        offsetsInfo = list()
        offsetsInfo.append(struct.unpack("I", self.__kbFile.read(4))[0])
        offsetsInfo.append(struct.unpack("I", self.__kbFile.read(4))[0])
        offsetsInfo.append(struct.unpack("i", self.__kbFile.read(4))[0])
        offsetsInfo.append(struct.unpack("i", self.__kbFile.read(4))[0])

        return offsetsInfo

    def __CheckKBFile(self) -> bool:
        signature = self.__kbFile.read(24)
        self.__kbFile.seek(265, 1)
        kbVersion = struct.unpack("i", self.__kbFile.read(4))[0]

        if (signature == b"IDD Knowledge Base File\x00") and (kbVersion == 1):
            self.__version = kbVersion
            return True

        if (signature == b"IDR Knowledge Base File\x00") and (kbVersion == 2):
            self.__version = kbVersion
            return True

        return False

    def GetFunctions(
            self,
            firstIndex: int = -1,
            lastIndex: int = -1) -> list[tuple[str, str]]:
        functions = list()

        if firstIndex == -1:
            firstIndex = 0

        if lastIndex == -1:
            lastIndex = self.__procCount

        for i in range(firstIndex, lastIndex + 1, 1):
            procInfo = self.GetProcInfo(i)

            if procInfo["DumpSz"] > 9:
                code = str()

                for y in range(procInfo["DumpSz"]):
                    b = procInfo["Dump"][y]

                    if procInfo["Reloc"][y] == 0xff:
                        code += "?? "
                    elif b < 0x10:
                        code += "0" + hex(b)[2:] + " "
                    else:
                        code += hex(b)[2:] + " "

                functions.append((procInfo["ProcName"].decode("utf-8"), code[:-1]))

        return functions

    def GetModuleID(self, moduleName: str) -> int:
        if moduleName == "" or self.__moduleCount == 0:
            return -1

        L = 0
        R = self.__moduleCount - 1

        while L < R:
            M = (L + R) // 2
            ID = self.__moduleOffsets[M][3]  # NameID
            nameLen = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0] + 2: self.__moduleOffsets[ID][0] + 4])[0]
            name = self.__kbMem[self.__moduleOffsets[ID][0] + 4: self.__moduleOffsets[ID][0] + 4 + nameLen].decode("utf-8")

            if moduleName.lower() <= name.lower():
                R = M
            else:
                L = M + 1

        ID = self.__moduleOffsets[R][3]
        nameLen = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0] + 2: self.__moduleOffsets[ID][0] + 4])[0]
        name = self.__kbMem[self.__moduleOffsets[ID][0] + 4: self.__moduleOffsets[ID][0] + 4 + nameLen].decode("utf-8")

        if moduleName == name:
            return struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0]: self.__moduleOffsets[ID][0] + 2])[0]

        return -1

    def GetProcIdx(self, moduleID: int, procName: str) -> int:
        """Return proc index by name in given ModuleID"""

        if moduleID == -1 or procName == "" or self.__procCount == 0:
            return -1

        L = 0
        R = self.__procCount - 1

        while True:
            M = (L + R) // 2
            # NameID
            ID = self.__procOffsets[M][3]
            nameLen = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0] + 2: self.__moduleOffsets[ID][0] + 4])[0]
            name = self.__kbMem[self.__procOffsets[ID][0] + 4: self.__procOffsets[ID][0] + 4 + nameLen].decode("utf-8")

            if procName < name:
                R = M - 1
            elif procName > name:
                L = M + 1
            else:
                # Find left boundary
                LN = M - 1
                while LN >= 0:
                    ID = self.__procOffsets[LN][3]  # NameID
                    nameLen = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0] + 2: self.__moduleOffsets[ID][0] + 4])[0]
                    name = self.__kbMem[self.__procOffsets[ID][0] + 4: self.__procOffsets[ID][0] + 4 + nameLen].decode("utf-8")

                    if procName != name:
                        break

                    LN -= 1

                # Find right boundary
                RN = M + 1

                while RN < self.__procCount:
                    ID = self.__procOffsets[RN][3]  # NameID
                    nameLen = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0] + 2: self.__moduleOffsets[ID][0] + 4])[0]
                    name = self.__kbMem[self.__procOffsets[ID][0] + 4: self.__procOffsets[ID][0] + 4 + nameLen].decode("utf-8")

                    if procName != name:
                        break

                    RN += 1

                N = LN + 1

                while N < RN:
                    ID = self.__procOffsets[N][3]  # NameID
                    ModID = struct.unpack("H", self.__kbMem[self.__moduleOffsets[ID][0]: self.__moduleOffsets[ID][0] + 2])[0]

                    if moduleID == ModID:
                        return N

                    N += 1

                return -1

            if L > R:
                return -1

    def GetProcIdxs(self, moduleID: int) -> tuple[int, int]:
        firstIndex = -1
        lastIndex = -1

        if moduleID != -1 or self.__procCount != 0:
            L = 0
            R = self.__procCount - 1

            while True:
                M = (L + R) // 2
                ID = self.__procOffsets[M][2]
                ModID = struct.unpack("H", self.__kbMem[self.__procOffsets[ID][0]: self.__procOffsets[ID][0] + 2])[0]

                if moduleID < ModID:
                    R = M - 1
                elif moduleID > ModID:
                    L = M + 1
                else:
                    firstIndex = M
                    lastIndex = M

                    LN = M - 1
                    while LN >= 0:
                        ID = self.__procOffsets[LN][2]
                        ModID = struct.unpack("H", self.__kbMem[self.__procOffsets[ID][0]: self.__procOffsets[ID][0] + 2])[0]

                        if moduleID != ModID:
                            break

                        firstIndex = LN
                        LN -= 1

                    RN = M + 1
                    while RN < self.__procCount:
                        ID = self.__procOffsets[RN][2]
                        ModID = struct.unpack("H", self.__kbMem[self.__procOffsets[ID][0]: self.__procOffsets[ID][0] + 2])[0]

                        if moduleID != ModID:
                            break

                        lastIndex = RN
                        RN += 1

                    return firstIndex, lastIndex

                if L > R:
                    return -1, -1

        return firstIndex, lastIndex

    def GetProcInfo(self, procIdx: int) -> int:

        if procIdx == -1:
            return 0

        procInfo = dict()
        rawProcInfo = self.__kbMem[self.__procOffsets[procIdx][0]: self.__procOffsets[procIdx][0] + self.__procOffsets[procIdx][1]]
        pos = 0

        procInfo["ModuleID"] = struct.unpack("H", rawProcInfo[pos: pos + 2])[0]
        pos += 2
        Len = struct.unpack("H", rawProcInfo[pos: pos + 2])[0]
        pos += 2
        procInfo["ProcName"] = rawProcInfo[pos: pos + Len]#.decode("utf-8")
        pos += Len + 1
        # procInfo["Embedded"] = rawProcInfo[pos]
        pos += 1
        # procInfo["DumpType"] = rawProcInfo[pos]
        pos += 1
        # procInfo["MethodKind"] = rawProcInfo[pos]
        pos += 1
        # procInfo["CallKind"] = rawProcInfo[pos]
        pos += 1
        # procInfo["VProc"] = struct.unpack("I", rawProcInfo[pos : pos + 4])[0]
        pos += 4
        Len = struct.unpack("H", rawProcInfo[pos: pos + 2])[0]
        pos += 2 + Len + 1

        # pInfo->TypeDef = TrimTypeName(String((char*)p)); p += Len + 1;

        # dumpTotal = struct.unpack("I", rawProcInfo[pos : pos + 4])[0]
        pos += 4
        procInfo["DumpSz"] = struct.unpack("I", rawProcInfo[pos: pos + 4])[0]
        pos += 4
        # procInfo["FixupNum"] = struct.unpack("I", rawProcInfo[pos : pos + 4])[0]
        pos += 4
        procInfo["Dump"] = b""
        if procInfo["DumpSz"]:
            procInfo["Dump"] = rawProcInfo[pos: pos + procInfo["DumpSz"]]
            procInfo["Reloc"] = rawProcInfo[pos + procInfo["DumpSz"]: pos + 2*procInfo["DumpSz"]]
        return procInfo


# 32bit
STRINGCOPY_2014_PATTERN = "53 85 d2 75 07 66 c7 00 00 00 eb 26 85 d2 7e 16 0f b7 19 66 89 18 66 85 db 74 17 83 c0 02 83 c1 02 4a 85 d2 7f ea 85 d2 75 08 83 e8 02 66 c7 00 00 00 5b c3"
ERRORAT_2014_PATTERN = "53 56 8b f2 8b d8 80 e3 7f 83 3d ?? ?? ?? ?? 00 74 0a 8b d6 8b c3 ff 15 ?? ?? ?? ?? 84 db 75 0d e8 ?? ?? ?? ?? 8b 98 ?? ?? ?? ?? eb 0f 80 fb 1c 77 0a 0f b6 c3 0f b6 98 ?? ?? ?? ?? 0f b6 c3 8b d6 e8 ?? ?? ?? ?? 5e 5b c3"
FINALIZERESSTRINGS_2013_PATTERN = "53 31 db 57 56 8b 3c 18 8d 74 18 04 8b 06 01 da 8b 4e 08 85 c9 74 07 49 74 0b 49 74 0f cc e8 ?? ?? ?? ?? eb 0c e8 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 83 c6 0c 4f 75 d5 5e 5f 5b c3"
OBJECT_FIELDADDRESS_2013_PATTERN = "53 56 57 31 c9 31 ff 8a 1a 50 8b 00 8b 70 bc 85 f6 74 18 66 8b 3e 85 ff 74 11 83 c6 06 8a 4e 06 38 d9 74 2c 8d 74 31 07 4f 75 f2 8b 40 d0 85 c0 75 d8 5a eb 39 8a 1a 8a 4e 06 eb e8 50 52 8d 46 06 e8 ?? ?? ?? ?? 31 c9 84 c0 5a 58 74 e7 eb 19 8a 5c 31 06 f6 c3 80 75 e3 32 1c 11 f6 c3 80 75 db 80 e3 df 75 cf 49 75 e7 8b 06 5a 01 d0 5f 5e 5b c3"
INITIALIZECONTROLWORD_2012_PATTERN = "e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 25 c0 ff 00 00 a3 ?? ?? ?? ?? c3"
ERRORAT_2011_PATTERN = "53 56 8b f2 8b d8 80 e3 7f 83 3d ?? ?? ?? ?? 00 74 0a 8b d6 8b c3 ff 15 ?? ?? ?? ?? 84 db 75 0d e8 ?? ?? ?? ?? 8b 98 ?? ?? ?? ?? eb 0f 80 fb 1b 77 0a 0f b6 c3 0f b6 98 ?? ?? ?? ?? 0f b6 c3 8b d6 e8 ?? ?? ?? ?? 5e 5b c3"
ERRORAT_2010_PATTERN = "53 56 8b f2 8b d8 80 e3 7f 83 3d ?? ?? ?? ?? 00 74 0a 8b d6 8b c3 ff 15 ?? ?? ?? ?? 84 db 75 0d e8 ?? ?? ?? ?? 8b 98 ?? ?? ?? ?? eb 0f 80 fb 1a 77 0a 0f b6 c3 0f b6 98 ?? ?? ?? ?? 0f b6 c3 8b d6 e8 ?? ?? ?? ?? 5e 5b c3"


def getDelphiVersion32() -> int:
    initTableAddr = IsExtendedInitTab()

    if initTableAddr:
        STRINGCOPY_addr = find_bytes(STRINGCOPY_2014_PATTERN)
        ERRORAT_2014_addr = find_bytes(ERRORAT_2014_PATTERN)

        if STRINGCOPY_addr != ida_idaapi.BADADDR or \
           ERRORAT_2014_addr != ida_idaapi.BADADDR:
            print("[INFO] Delphi version: >= 2014")
            return 2014

        FINALIZERESSTRINGS_addr = find_bytes(FINALIZERESSTRINGS_2013_PATTERN)
        OBJECT_FIELDADDRESS_addr = find_bytes(OBJECT_FIELDADDRESS_2013_PATTERN)

        if OBJECT_FIELDADDRESS_addr != ida_idaapi.BADADDR or \
           FINALIZERESSTRINGS_addr != ida_idaapi.BADADDR:
            print("[INFO] Delphi version: 2013")
            return 2013

        INITIALIZECONTROLWORD_addr = find_bytes(INITIALIZECONTROLWORD_2012_PATTERN)

        if INITIALIZECONTROLWORD_addr != ida_idaapi.BADADDR:
            print("[INFO] Delphi version: 2012")
            return 2012

        ERRORAT_2011_addr = find_bytes(ERRORAT_2011_PATTERN)

        if ERRORAT_2011_addr != ida_idaapi.BADADDR:
            print("[INFO] Delphi version: 2011")
            return 2011

        ERRORAT_2010_addr = find_bytes(ERRORAT_2010_PATTERN)

        if ERRORAT_2010_addr != ida_idaapi.BADADDR:
            print("[INFO] Delphi version: 2010")
            return 2010

        print("[INFO] Delphi version: UNKNOWN")
        return 2014

    print("[INFO] Delphi version: <= 2009")
    return 2009


# 64bit
STRINGCOPY_2014_PATTERN64 = "85 d2 75 07 66 c7 01 00 00 eb 2a 85 d2 7e 1b 49 0f b7 00 66 89 01 66 85 c0 74 1a 48 83 c1 02 49 83 c0 02 83 ea 01 85 d2 7f e5 90 85 d2 75 06 66 c7 41 fe 00 00 c3"
ERRORAT_2014_PATTERN64 = "56 53 48 83 ec 28 89 cb 48 89 d6 80 e3 7f 48 83 3d ?? ?? ?? ?? 00 74 0b 89 d9 48 89 f2 ff 15 ?? ?? ?? ?? 84 db 75 0f e8 ?? ?? ?? ?? 48 0f b6 98 ?? ?? ?? ?? eb 15 80 fb 1c 77 10 48 8d 05 ?? ?? ?? ?? 48 0f b6 db 48 0f b6 1c 18 48 0f b6 cb 48 89 f2 e8 ?? ?? ?? ?? 48 83 c4 28 5b 5e c3"
OBJECT_CLASSNAME_2013_PATTERN64 = "53 48 83 ec 20 48 89 d3 48 89 d8 48 8b 91 78 ff ff ff 48 89 c1 e8 ?? ?? ?? ?? 48 89 d8 48 83 c4 20 5b c3"
CLASSCREATE_2013_PATTERN64 = "48 83 ec 28 48 89 c8 84 d2 7c 06 48 89 c1 ff 50 d0 48 83 c4 28 c3"
INITIALIZECONTROLWORD_2012_PATTERN64 = "48 83 ec 28 c7 05 ?? ?? ?? ?? 03 00 00 00 e8 ?? ?? ?? ?? 66 81 e0 3f 1f 66 89 05 ?? ?? ?? ?? 48 83 c4 28 c3"


def getDelphiVersion64() -> int:
    STRINGCOPY_addr = find_bytes(STRINGCOPY_2014_PATTERN64)
    ERRORAT_addr = find_bytes(ERRORAT_2014_PATTERN64)
    if ERRORAT_addr != ida_idaapi.BADADDR or \
       STRINGCOPY_addr != ida_idaapi.BADADDR:
        print("[INFO] Delphi version: >= 2014")
        return 2014

    OBJECT_CLASSNAME_addr = find_bytes(OBJECT_CLASSNAME_2013_PATTERN64)
    CLASSCREATE_addr = find_bytes(CLASSCREATE_2013_PATTERN64)

    if OBJECT_CLASSNAME_addr != ida_idaapi.BADADDR or \
       CLASSCREATE_addr != ida_idaapi.BADADDR:
        print("[INFO] Delphi version: 2013")
        return 2013

    INITIALIZECONTROLWORD_addr = find_bytes(INITIALIZECONTROLWORD_2012_PATTERN64)

    if INITIALIZECONTROLWORD_addr != ida_idaapi.BADADDR:
        print("[INFO] Delphi version: 2012")
        return 2012

    print("[INFO] Delphi version: UNKNOWN")
    return 2014


def GetDelphiVersion() -> int:
    ida_kernwin.show_wait_box("Trying to determine Delphi version...")
    try:
        if Is64bit():
            return getDelphiVersion64()
        else:
            return getDelphiVersion32()
    finally:
        ida_kernwin.hide_wait_box()
