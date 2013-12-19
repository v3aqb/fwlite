#!/usr/bin/env python
# coding:utf-8
# Copyright (c) 2013 v3aqb

from __future__ import print_function, division, unicode_literals

__version__ = '0.1'

import sys
import wx

TRAY_ICON = './fgfw-lite/taskbar.ico'


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
        create_menu_item(menu, 'Show Toggle', self.showtoggle)
        menu.AppendSeparator()
        create_menu_item(menu, 'Exit', self.on_exit)
        return menu

    def set_icon(self, path):
        icon = wx.IconFromBitmap(wx.Bitmap(path))
        self.SetIcon(icon, 'fgfwlite-wx')

    def showtoggle(self, event):
        self.win.Show(not self.win.IsShown())

    def on_exit(self, event):
        sys.exit()


class Frame(wx.Frame):
    def __init__(
            self, parent=None, id=wx.ID_ANY, title='fgfwlite-wx', pos=wx.DefaultPosition,
            size=wx.DefaultSize, style=wx.DEFAULT_FRAME_STYLE):
        wx.Frame.__init__(self, parent, id, title, pos, size, style)
        self.SetClientSize(wx.Size(632, 480))
        self.SetIcon = wx.IconFromBitmap(wx.Bitmap(TRAY_ICON))
        panel = wx.Panel(self, wx.ID_ANY)

        self.consoleText = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.consoleText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))

        self.inputText = wx.TextCtrl(panel)
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
        self.Bind(wx.EVT_BUTTON, self.do_send, sendbutton)
        self.Bind(wx.EVT_CLOSE, self.on_exit)

    def do_send(self, event):
        pass

    def on_exit(self, event):
        self.Show(False)


def main():
    app = wx.App()
    TrayIcon()
    app.MainLoop()


if __name__ == '__main__':
    main()
