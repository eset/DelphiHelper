#
# This module implements DelphiHelper exception
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


class DelphiHelperError(Exception):

    def __init__(self, msg: str = str(), msgType: int = 0) -> None:
        Exception.__init__(self, msg)
        self.msg = msg

        if msgType == 0:
            self.msgType = "[ERROR]"
        else:
            self.msgType = "[WARNING]"

    def print(self) -> None:
        if self.msg:
            print(f"{self.msgType} {self.msg}")
