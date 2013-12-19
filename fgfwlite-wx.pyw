#!/usr/bin/env python
# coding:utf-8
# Copyright (c) 2013 v3aqb

from __future__ import print_function, division, unicode_literals

__version__ = '0.1'

import os
import sys
import wx

WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/'))
os.chdir(WORKINGDIR)
TRAY_ICON = '%s/fgfw-lite/taskbar.ico' % WORKINGDIR
PYTHON = '%s/Python27/python27.exe' % WORKINGDIR if sys.platform.startswith('win') else '/usr/bin/env python2.7'


def create_menu_item(menu, label, func):
    item = wx.MenuItem(menu, -1, label)
    menu.Bind(wx.EVT_MENU, func, id=item.GetId())
    menu.AppendItem(item)
    return item


class TrayIcon(wx.TaskBarIcon):
    def __init__(self):
        super(TrayIcon, self).__init__()
        self.set_icon(TRAY_ICON)
        self.Bind(wx.EVT_TASKBAR_LEFT_DOWN, self.showtoggle)
        self.win = Frame()
        self.win.Centre()

    def CreatePopupMenu(self):
        menu = wx.Menu()
        create_menu_item(menu, '显示/隐藏', self.showtoggle)
        create_menu_item(menu, '重新载入', self.reload)
        menu.AppendSeparator()
        create_menu_item(menu, '退出', self.on_exit)
        return menu

    def set_icon(self, path):
        icon = wx.IconFromBitmap(wx.Bitmap(path))
        self.SetIcon(icon, 'fgfwlite-wx')

    def showtoggle(self, event):
        self.win.Show(not self.win.IsShown())

    def reload(self, event):
        self.win.process.GetOutputStream().write('exit()\n')
        self.win.consoleText.SetValue('')
        self.win.startProcess()

    def on_exit(self, event):
        self.win.process.GetOutputStream().write('exit()\n')
        sys.exit()


class Frame(wx.Frame):
    def __init__(
            self, parent=None, id=wx.ID_ANY, title='fgfwlite-wx', pos=wx.DefaultPosition,
            size=wx.DefaultSize, style=wx.DEFAULT_FRAME_STYLE):
        wx.Frame.__init__(self, parent, id, title, pos, size, style)
        self.SetClientSize(wx.Size(632, 480))
        self.SetIcon(wx.IconFromBitmap(wx.Bitmap(TRAY_ICON)))
        self.process = None
        self.Bind(wx.EVT_IDLE, self.OnIdle)

        panel = wx.Panel(self, wx.ID_ANY)

        self.consoleText = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.consoleText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))

        self.inputText = wx.TextCtrl(panel, style=wx.TE_PROCESS_ENTER)
        self.inputText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))

        sendbutton = wx.Button(panel, wx.ID_ANY, u'Send')

        box1 = wx.BoxSizer(wx.HORIZONTAL)
        box1.Add(self.inputText, 1, wx.EXPAND)
        box1.Add(sendbutton, 0)

        box = wx.BoxSizer(wx.VERTICAL)
        box.Add(self.consoleText, 1, wx.EXPAND)
        box.Add(box1, 0, wx.EXPAND)
        panel.SetSizer(box)

        # bind event
        self.Bind(wx.EVT_BUTTON, self.on_send, sendbutton)
        self.Bind(wx.EVT_CLOSE, self.on_exit)
        self.Bind(wx.EVT_TEXT_ENTER, self.on_send, self.inputText)

        self.startProcess()

    def startProcess(self):
        cmd = '/usr/bin/env python2.7 ./fgfw-lite/fgfw-lite.py'
        self.process = wx.Process(self)
        self.process.Redirect()
        wx.Execute(cmd, wx.EXEC_ASYNC, self.process)

    def on_send(self, event):
        text = self.inputText.GetValue()
        self.inputText.SetValue('')
        self.consoleText.AppendText(text + '\n')
        self.process.GetOutputStream().write(text + '\n')
        self.inputText.SetFocus()

    def on_exit(self, event):
        self.Show(False)

    def __del__(self):
        if self.process is not None:
            self.process.Detach()
            self.process.CloseOutput()
            self.process = None

    def OnIdle(self, event):
        if self.process is not None:
            if self.process.IsErrorAvailable():
                self.addText(self.process.GetErrorStream().read())
            if self.process.IsInputAvailable():
                self.addText(self.process.GetInputStream().read())

    def addText(self, text):
        console = self.consoleText.GetValue().splitlines()
        if len(console) > 300:
            self.consoleText.SetValue('\n'.join(console[len(console) - 500:]))
        self.consoleText.AppendText(text)


def main():
    app = wx.App()
    TrayIcon()
    app.MainLoop()


if __name__ == '__main__':
    main()
