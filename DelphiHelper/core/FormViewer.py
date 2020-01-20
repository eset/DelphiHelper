#
# This module allows to show Delphi's forms extracted from DFMs
#
# Copyright (c) 2020-2024 ESET
# Author: Juraj Horňák <juraj.hornak@eset.com>
# See LICENSE file for redistribution.


import ida_kernwin
from DelphiHelper.core.DelphiForm import DelphiObject
from DelphiHelper.ui.FormViewerUI import FormViewerUI


class DelphiFormViewer(ida_kernwin.PluginForm):

    def __init__(
            self,
            formList: list[tuple[DelphiObject, list[tuple[str, int]], int]]
            ) -> None:
        ida_kernwin.PluginForm.__init__(self)
        self.parent = None
        self.__formList = formList

    def OnCreate(self, form) -> None:
        if len(self.__formList):
            FormViewerUI(self.FormToPyQtWidget(form), self.__formList)

    def OnClose(self, form) -> None:
        global _DelphiFormViewer
        del _DelphiFormViewer

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self,
            "Delphi Form Viewer",
            options=ida_kernwin.PluginForm.WOPN_PERSIST
        )


def FormViewer(
        formList: list[tuple[DelphiObject, list[tuple[str, int]], int]]
        ) -> None:
    global _DelphiFormViewer

    try:
        _DelphiFormViewer
    except Exception:
        _DelphiFormViewer = DelphiFormViewer(formList)

    _DelphiFormViewer.Show()
