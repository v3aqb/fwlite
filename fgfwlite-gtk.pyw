#!/usr/bin/env python
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '1.6'

import sys
import os
import thread

try:
    import pygtk
    pygtk.require('2.0')
    import gtk
    gtk.gdk.threads_init()
except Exception:
    sys.exit(os.system(u'gdialog --title "FGFW-Lite GTK" --msgbox "请安装 python-gtk2" 15 60'.encode(sys.getfilesystemencoding() or sys.getdefaultencoding(), 'replace')))
try:
    import pynotify
    pynotify.init('FGFW-Lite Notify')
except ImportError:
    pynotify = None
try:
    import appindicator
except ImportError:
    appindicator = None
try:
    import vte
except ImportError:
    sys.exit(gtk.MessageDialog(None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'请安装 python-vte').run())


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        import time
        time.sleep(seconds)
        return target(*args, **kwargs)
    return thread.start_new_thread(wrap, args, kwargs)


def drop_desktop():
    filename = os.path.abspath(__file__)
    dirname = os.path.dirname(filename)
    DESKTOP_FILE = '''\
#!/usr/bin/env xdg-open
[Desktop Entry]
Type=Application
Name=FGFW-Lite GTK
Comment=FGFW-Lite GTK Launcher
Categories=Network;Proxy;
Exec=/usr/bin/env python "%s"
Icon=%s/fgfw-lite/taskbar.ico
Terminal=false
StartupNotify=true
''' % (filename, dirname)
    for dirname in map(os.path.expanduser, ['~/Desktop', u'~/桌面']):
        if os.path.isdir(dirname):
            filename = os.path.join(dirname, 'fgfwlite-gtk.desktop')
            with open(filename, 'w') as fp:
                fp.write(DESKTOP_FILE)
            os.chmod(filename, 0755)


#gtk.main_quit = lambda: None
#appindicator = None


class GoAgentGTK:

    command = ['/usr/bin/env', 'python2.7', './fgfw-lite/fgfw-lite.py']
    message = u'FGFW-Lite已经启动，单击托盘图标可以最小化'
    message = None
    fail_message = u'FGFW-Lite启动失败，请查看控制台窗口的错误信息。'

    def __init__(self, window, terminal):
        self.window = window
        self.window.set_size_request(652, 447)
        self.window.set_position(gtk.WIN_POS_CENTER)
        self.window.connect('delete-event', self.delete_event)
        self.terminal = terminal
        for cmd in ('python2.7', 'python27', 'python2'):
            if os.system('which %s' % cmd) == 0:
                self.command[1] = cmd
                break

        self.window.add(terminal)
        self.childpid = self.terminal.fork_command(self.command[0], self.command, os.getcwd())
        if self.childpid > 0:
            self.childexited = self.terminal.connect('child-exited', self.on_child_exited)
            self.window.connect('delete-event', lambda w, e: gtk.main_quit())
        else:
            self.childexited = None

        spawn_later(0.5, self.show_startup_notify)

        logo_filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), './fgfw-lite/taskbar.ico')
        self.window.set_icon_from_file(logo_filename)

        if appindicator:
            self.trayicon = appindicator.Indicator('FGFW-Lite', 'indicator-messages', appindicator.CATEGORY_APPLICATION_STATUS)
            self.trayicon.set_status(appindicator.STATUS_ACTIVE)
            self.trayicon.set_attention_icon('indicator-messages-new')
            self.trayicon.set_icon(logo_filename)
            self.trayicon.set_menu(self.make_menu())
        else:
            self.trayicon = gtk.StatusIcon()
            self.trayicon.set_from_file(logo_filename)
            self.trayicon.connect('popup-menu', lambda i, b, t: self.make_menu().popup(None, None, gtk.status_icon_position_menu, b, t, self.trayicon))
            self.trayicon.connect('activate', self.show_hide_toggle)
            self.trayicon.set_tooltip('fgfwlite-gtk')
            self.trayicon.set_visible(True)

    def make_menu(self):
        menu = gtk.Menu()
        itemlist = [(u'\u663e\u793a/\u9690\u85cf', self.show_hide_toggle),
                    (u'\u91cd\u65b0\u8f7d\u5165', self.on_reload),
                    (u'\u9000\u51fa', self.on_quit)]
        for text, callback in itemlist:
            item = gtk.MenuItem(text)
            item.connect('activate', callback)
            item.show()
            menu.append(item)
        menu.show()
        return menu

    def show_notify(self, message=None, timeout=None):
        if pynotify and message:
            notification = pynotify.Notification('FGFW-Lite Notify', message)
            notification.set_hint('x', 200)
            notification.set_hint('y', 400)
            if timeout:
                notification.set_timeout(timeout)
            notification.show()

    def show_startup_notify(self):
        if self.check_child_exists():
            self.show_notify(self.message, timeout=3)

    def check_child_exists(self):
        if self.childpid <= 0:
            return False
        cmd = 'ps -p %s' % self.childpid
        lines = os.popen(cmd).read().strip().splitlines()
        if len(lines) < 2:
            return False
        return True

    def on_child_exited(self, term):
        if self.terminal.get_child_exit_status() == 0:
            gtk.main_quit()
        else:
            self.show_notify(self.fail_message)

    def on_show(self, widget, data=None):
        self.window.show_all()
        self.window.present()
        self.terminal.feed('\r')

    def on_hide(self, widget, data=None):
        self.window.hide_all()

    def on_stop(self, widget, data=None):
        if self.childexited:
            self.terminal.disconnect(self.childexited)
        os.system('kill -9 %s' % self.childpid)

    def on_reload(self, widget, data=None):
        if self.childexited:
            self.terminal.disconnect(self.childexited)
        os.system('kill -9 %s' % self.childpid)
        self.on_show(widget, data)
        self.childpid = self.terminal.fork_command(self.command[0], self.command, os.getcwd())
        self.childexited = self.terminal.connect('child-exited', lambda term: gtk.main_quit())

    def show_hide_toggle(self, widget, data=None):
        if self.window.get_property('visible'):
            self.on_hide(widget, data)
        else:
            self.on_show(widget, data)

    def on_quit(self, widget, data=None):
        gtk.main_quit()

    def delete_event(self, widget, data=None):
        self.on_hide(widget, data)
        # 默认最小化至托盘
        return True


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    drop_desktop()

    window = gtk.Window()
    terminal = vte.Terminal()
    GoAgentGTK(window, terminal)
    gtk.main()

if __name__ == '__main__':
    main()
