#
# This module allows to search for Delphi's DFM in Delphi binary
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_offset
import idautils
import struct
from DelphiHelper.util.ida import Byte, Word, Dword, find_bytes


class DFMFinder():

    def __init__(self) -> None:
        self.__rsrcSecAddr = self.__GetResourceSectionAddress()
        self.__DFMlist = list()
        self.__ExtractDFM()

    def GetDFMList(self) -> list[tuple[int, int]]:
        return self.__DFMlist

    def __CheckDFMSignature(self, addr: int) -> bool:
        if chr(Byte(addr)) == "T" and \
           chr(Byte(addr + 1)) == "P" and \
           chr(Byte(addr + 2)) == "F" and \
           chr(Byte(addr + 3)) == "0":
            return True
        else:
            return False

    def __GetResourceSectionAddress(self) -> int:
        pe = idautils.peutils_t()

        resourceDirectoryOffset = 0x88
        if not pe or len(pe.header()) < resourceDirectoryOffset + 4:
            return 0

        resourceDirectory = pe.header()[resourceDirectoryOffset:resourceDirectoryOffset+4]
        resourceDirectoryRVA = struct.unpack("i", resourceDirectory)[0]

        if resourceDirectoryRVA:
            return ida_nalt.get_imagebase() + resourceDirectoryRVA
        else:
            return 0

    def __GetRCDATAAddr(self) -> int:
        numOfDirEntries = self.__GetNumberOfDirEntries(self.__rsrcSecAddr)
        addr = self.__rsrcSecAddr + 16

        for i in range(numOfDirEntries):
            # RCDATA
            if Dword(addr) == 10 and Dword(addr + 4) & 0x80000000 != 0:
                return self.__rsrcSecAddr + (Dword(addr + 4) & 0x7FFFFFFF)
            addr += 8
        return 0

    def __GetNumberOfDirEntries(self, tableAddr: int) -> int:
        return Word(tableAddr + 12) + Word(tableAddr + 14)

    def __ExtractDFMFromResource(self) -> None:
        print("[INFO] Searching for DFM in loaded resource section...")

        if self.__rsrcSecAddr == 0:
            print("[INFO] The resource directory is empty.")
            return

        if ida_offset.can_be_off32(self.__rsrcSecAddr) != ida_idaapi.BADADDR:
            RCDATAaddr = self.__GetRCDATAAddr()

            if RCDATAaddr != 0:
                RCDATAaddrEntryCount = self.__GetNumberOfDirEntries(RCDATAaddr)
                addr = RCDATAaddr + 16

                for i in range(RCDATAaddrEntryCount):
                    if Dword(addr) & 0x80000000 != 0:
                        strAddr = (self.__rsrcSecAddr
                                   + (Dword(addr) & 0x7FFFFFFF))

                        if Dword(addr + 4) & 0x80000000 != 0:
                            dirTableAddr = (self.__rsrcSecAddr
                                            + (Dword(addr + 4) & 0x7FFFFFFF))

                            if self.__GetNumberOfDirEntries(dirTableAddr) == 1:
                                DFMDataAddr = (ida_nalt.get_imagebase()
                                               + Dword(self.__rsrcSecAddr
                                               + Dword(dirTableAddr + 20)))

                                DFMDataSizeAddr = (self.__rsrcSecAddr
                                                   + Dword(dirTableAddr + 20)
                                                   + 4)
                                DFMDataSize = Dword(DFMDataSizeAddr)

                                if self.__CheckDFMSignature(DFMDataAddr):
                                    self.__DFMlist.append((DFMDataAddr, DFMDataSize))
                    addr += 8
            else:
                print("[WARNING] The resource section seems to be corrupted!")
        else:
            print("[WARNING] The resource section not found! Make sure the resource section is loaded by IDA.")
            ida_kernwin.warning("The resource section not found!\nMake sure the resource section is loaded by IDA.")

    def __ExtractDFMFromBinary(self) -> None:
        print("[INFO] Searching for DFM in loaded binary...")

        self.__DFMlist = list()
        startAddr = 0
        counter = 0

        while True:
            # 0x0TPF0
            dfmAddr = find_bytes("00 54 50 46 30", startAddr)

            if dfmAddr == ida_idaapi.BADADDR:
                break

            if counter != 0 and Byte(dfmAddr + 5) != 0:  # FP
                print(f"[INFO] Found DFM: 0x{dfmAddr:x}")
                self.__DFMlist.append((dfmAddr + 1, 10000000))

            counter += 1
            startAddr = dfmAddr + 1

    def __ExtractDFM(self) -> None:
        self.__ExtractDFMFromResource()

        if len(self.__DFMlist) == 0:
            self.__ExtractDFMFromBinary()

        if len(self.__DFMlist) == 0:
            print("[INFO] DFM not found.")
