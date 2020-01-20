#
# This script downloads IDR Knowledge Base files used by DelphiHelper plugin
#
# The script downloads KB files from IDR projects:
# https://github.com/crypto2011/IDR,
# https://github.com/crypto2011/IDR64,
# which are licensed under the MIT License:
# https://github.com/crypto2011/IDR/blob/master/LICENSE
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import os
import py7zr
import shutil
import sys
import urllib.error
import urllib.request


IDRKBDIR = "IDR_KB"
PLUGIN_PATH = os.path.expandvars("$HOME/.idapro/plugins/DelphiHelper/")
if sys.platform == "win32":
    PLUGIN_PATH = os.path.expandvars("%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\DelphiHelper\\")
IDR_PATH = os.path.join(PLUGIN_PATH, IDRKBDIR)

DOWNLOADLIST_IDR = [
    ("kb2005.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2005.7z"),
    ("kb2006.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2006.7z"),
    ("kb2007.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2007.7z"),
    ("kb2009.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2009.7z"),
    ("kb2010.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2010.7z"),
    ("kb2011.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2011.7z"),
    ("kb2012.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2012.7z"),
    ("kb2013.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2013.7z"),
    ("kb2014.7z", "https://raw.githubusercontent.com/crypto2011/IDR/master/kb2014.7z")
]

DOWNLOADLIST_IDR64 = [
    ("syskb2012.bin", "https://raw.githubusercontent.com/crypto2011/IDR64/master/syskb2012.bin"),
    ("syskb2013.bin", "https://raw.githubusercontent.com/crypto2011/IDR64/master/syskb2013.bin"),
    ("syskb2014.bin", "https://raw.githubusercontent.com/crypto2011/IDR64/master/syskb2014.bin")
]


def downloadFile(url: str, filename: str) -> bool:
    print(f"[INFO] Downloading file from: {url}")

    try:
        urllib.request.urlretrieve(url, filename)
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTPError: {e.msg} ({e.url})")
        return False

    print(f"[INFO] The file saved as \"{filename}\"")
    return True

def unpack7z(archivePath: str, destinationFolder: str) -> bool:
    print(f"[INFO] Unpacking archive \"{archivePath}\"...")

    if not py7zr.is_7zfile(archivePath):
        print(f"[ERROR] {archivePath} is not valid 7z file.")
        return False

    with py7zr.SevenZipFile(archivePath, "r") as archive:
        archive.extractall(path=destinationFolder)

    return True

def init() -> bool:
    try:
        if not os.path.exists(PLUGIN_PATH):
            print(f"[ERROR] DelphiHelper directory \"{PLUGIN_PATH}\" not found!")
            print("[INFO] Read the README.md for DelphiHelper installation location.")
            return False

        if os.path.exists(IDR_PATH):
            shutil.rmtree(IDR_PATH)

        os.mkdir(IDR_PATH)
        os.mkdir(os.path.join(IDR_PATH, "IDR"))
        os.mkdir(os.path.join(IDR_PATH, "IDR64"))
    except FileNotFoundError as e:
        raise e

    return True

def downloadIDRKB() -> None:
    if init():
        print("[INFO] Downloading IDR Knowledge Base files...")
        for filename, url in DOWNLOADLIST_IDR64:
            downloadFile(url, os.path.join(IDR_PATH, "IDR64", filename))

        for filename, url in DOWNLOADLIST_IDR:
            downloadFile(url, filename)
            unpack7z(filename, os.path.join(IDR_PATH, "IDR"))
            os.remove(filename)

downloadIDRKB()
