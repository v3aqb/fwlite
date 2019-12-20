# coding: utf-8
import os
import sys
import traceback
import urllib.request
from urllib.request import Request

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QWidget, QMenu

from .translate import translate
_tr = translate

try:
    import pynotify
    pynotify.init('FWLite Notify')
except ImportError:
    pynotify = None

proxy_handler = urllib.request.ProxyHandler({})
opener = urllib.request.build_opener(proxy_handler)
urlopen = opener.open


def setIEproxy(enable, proxy=u'', override=u'<local>'):
    import ctypes
    try:
        import _winreg as winreg
    except ImportError:
        import winreg
    if enable == 0:
        proxy = u''
    INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                       r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                       0, winreg.KEY_WRITE)

    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, enable)
    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, winreg.REG_SZ, proxy)
    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyOverride', 0, winreg.REG_SZ, override)

    ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)


def parse_hostport(host, default_port=80):
    if isinstance(host, bytes):
        host = host.decode()
    import re
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


class SystemTrayIcon(QSystemTrayIcon):

    def __init__(self, icon, window, parent=None):
        QSystemTrayIcon.__init__(self, icon, parent)
        self.menu = QMenu(parent)
        self.window = window
        self.resolve = RemoteResolve(self.window)

        self.create_menu()

        self.setContextMenu(self.menu)

    def create_actions(self):
        self.showToggleAction = QtWidgets.QAction(_tr("SystemTrayIcon", "show_toggle"), self, triggered=self.window.showToggle)
        self.reloadAction = QtWidgets.QAction(_tr("SystemTrayIcon", "reload"), self, triggered=self.window.reload)
        self.flushDNSAction = QtWidgets.QAction(_tr("SystemTrayIcon", "clear_dns_cache"), self, triggered=self.flushDNS)
        self.remoteDNSAction = QtWidgets.QAction(_tr("SystemTrayIcon", "remote_dns_resolve"), self, triggered=self.remoteDNS)
        self.settingDNSAction = QtWidgets.QAction(_tr("SystemTrayIcon", "Settings"), self, triggered=self.window.openSetting)
        self.quitAction = QtWidgets.QAction(_tr("SystemTrayIcon", "exit"), self, triggered=self.on_Quit)

    def create_menu(self):
        self.create_actions()

        self.menu.addAction(self.showToggleAction)
        self.menu.addAction(self.reloadAction)

        if sys.platform.startswith('win'):
            self.settingIEproxyMenu = self.menu.addMenu(_tr("SystemTrayIcon", "set_proxy"))
            self.settingIEproxyMenu.clear()

            profile = [int(x) for x in self.window.conf.get('FWLite', 'profile', fallback='13')]
            profile_label = {0: 'direct',
                             1: 'gfwlist_auto',
                             2: 'encrypt_all',
                             3: 'bypass_china',
                             4: 'bypass_LAN',
                             5: 'bypass_localhost'}
            for i, p in enumerate(profile):

                title = _tr("SystemTrayIcon", profile_label[p])
                if i <= 5:
                    self.settingIEproxyMenu.addAction(QtWidgets.QAction(title, self, triggered=getattr(self, 'set_ie_p%d' % i)))
            act = QtWidgets.QAction(_tr("SystemTrayIcon", "No Proxy"), self, triggered=lambda: setIEproxy(0))
            self.settingIEproxyMenu.addAction(act)

        advancedMenu = self.menu.addMenu(_tr("SystemTrayIcon", "advanced"))
        advancedMenu.addAction(self.flushDNSAction)
        advancedMenu.addAction(self.remoteDNSAction)

        self.menu.addAction(self.settingDNSAction)
        self.menu.addSeparator()
        self.menu.addAction(self.quitAction)

        self.setToolTip(u'FWLite')
        self.setContextMenu(self.menu)
        self.activated.connect(self.on_trayActive)

    def set_ie_p0(self):
        setIEproxy(1, u'127.0.0.1:%d' % self.window.port)

    def set_ie_p1(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.window.port + 1))

    def set_ie_p2(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.window.port + 2))

    def set_ie_p3(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.window.port + 3))

    def set_ie_p4(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.window.port + 4))

    def set_ie_p5(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.window.port + 5))

    def flushDNS(self):
        if sys.platform.startswith('win'):
            os.system('ipconfig.exe /flushdns')
        elif sys.platform.startswith('darwin'):
            os.system('dscacheutil -flushcache')
        elif sys.platform.startswith('linux'):
            self.showMessage_(u'for Linux system, run "sudo /etc/init.d/nscd restart"')
        else:
            self.showMessage_(u'OS not recognised')

    def remoteDNS(self):
        self.resolve.show()

    def on_Quit(self):
        if sys.platform.startswith('win') and self.window.ieproxy == 1:
            setIEproxy(0)
        self.window.killProcess()
        self.hide()
        QApplication.instance().quit()

    def on_trayActive(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.window.showToggle()

    def showMessage_(self, msg, timeout=10):
        self.showMessage(
            'FWLite',
            msg, QSystemTrayIcon.Information,
            timeout * 1000)


class RemoteResolve(QWidget):

    def __init__(self, window, parent=None):
        super(RemoteResolve, self).__init__()
        self.window = window
        self.setWindowIcon(self.window.windowIcon())

        self.setObjectName("remote_resolver")
        self.resize(300, 200)
        self.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setContentsMargins(6, 6, 6, 6)
        self.verticalLayout.setObjectName("verticalLayout")
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setObjectName("formLayout")
        self.hostLabel = QtWidgets.QLabel(self)
        self.hostLabel.setObjectName("hostLabel")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.hostLabel)
        self.hostLineEdit = QtWidgets.QLineEdit(self)
        self.hostLineEdit.setObjectName("hostLineEdit")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.hostLineEdit)
        self.serverLabel = QtWidgets.QLabel(self)
        self.serverLabel.setObjectName("serverLabel")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.serverLabel)
        self.serverlineEdit = QtWidgets.QLineEdit(self)
        self.serverlineEdit.setObjectName("serverlineEdit")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.serverlineEdit)
        self.proxyLabel = QtWidgets.QLabel(self)
        self.proxyLabel.setObjectName("serverLabel")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.proxyLabel)
        self.proxyBox = QtWidgets.QComboBox(self)
        self.proxyBox.setObjectName("proxyBox")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.proxyBox)
        self.verticalLayout.addLayout(self.formLayout)
        self.goButton = QtWidgets.QPushButton(self)
        self.goButton.setObjectName("goButton")
        self.verticalLayout.addWidget(self.goButton)
        self.resultTextEdit = QtWidgets.QPlainTextEdit(self)
        self.resultTextEdit.setAcceptDrops(False)
        self.resultTextEdit.setUndoRedoEnabled(False)
        self.resultTextEdit.setReadOnly(True)
        self.resultTextEdit.setObjectName("resultTextEdit")
        self.verticalLayout.addWidget(self.resultTextEdit)

        self.setWindowTitle(_tr("remote_resolver", "Remote Resolver"))
        self.hostLabel.setText(_tr("remote_resolver", "Hostname:"))
        self.hostLineEdit.setText(_tr("remote_resolver", "www.google.com"))
        self.serverLabel.setText(_tr("remote_resolver", "DNS Server:"))
        self.serverlineEdit.setText(_tr("remote_resolver", "8.8.8.8"))
        self.proxyLabel.setText(_tr("remote_resolver", "Proxy:"))
        self.goButton.setText(_tr("remote_resolver", "Resolve"))

        self.goButton.clicked.connect(self.do_resolve)

    def set_proxy(self, proxy_list):
        proxy_list = [item for item in proxy_list if item.startswith('FWLITE:')]
        proxy_list.insert(0, '_D1R3CT_')
        proxy = self.proxyBox.currentText()
        self.proxyBox.clear()
        self.proxyBox.addItems(proxy_list)
        self.proxyBox.setCurrentText(proxy)

    def do_resolve(self):
        self.resultTextEdit.setPlainText(_tr("MainWindow", "resolving_notice"))
        hostname = self.hostLineEdit.text()
        dns_server = self.serverlineEdit.text()
        proxy = self.proxyBox.currentText()

        self.resultTextEdit.setPlainText('resolving %s with %s via %s' % (hostname, dns_server, proxy))
        import base64
        import dnslib
        import socket
        import struct
        import urllib.parse
        result = []
        try:
            if proxy:
                self.resultTextEdit.setPlainText('get proxy')
                _name = base64.urlsafe_b64encode(proxy.encode()).decode()
                req = Request('http://127.0.0.1:%d/api/proxy/%s' % (self.window.port, _name), headers=self.window.api_auth)
                proxy = urlopen(req, timeout=1).read().decode()
                self.resultTextEdit.setPlainText(proxy)
            # connect
            if proxy:
                # connect to proxy
                parse = urllib.parse.urlparse(proxy)
                address = (parse.hostname, parse.port)
                soc = socket.create_connection(address, 3)
                # connect to server
                server = parse_hostport(dns_server, 53)
                s = ['CONNECT %s:%s HTTP/1.1\r\n' % server, ]
                s.append('Host: %s:%s\r\n\r\n' % server)
                soc.sendall(''.join(s).encode())
                rfile = soc.makefile('rb')
                for _ in range(10):
                    data = rfile.readline()
                    if not data.strip():
                        break
            else:
                # connect to server
                server = parse_hostport(dns_server, 53)
                soc = socket.create_connection(server, 3)
                rfile = soc.makefile('rb')

            for _ in range(10):
                # send request
                query = dnslib.DNSRecord.question(hostname, qtype='ANY')
                query_data = query.pack()
                data = struct.pack('>h', len(query_data)) + query_data
                soc.sendall(bytes(data))

                # read response
                soc.settimeout(5)

                reply_data_length = rfile.read(2)
                reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])

                # parse record
                record = dnslib.DNSRecord.parse(reply_data)
                result.extend(['%s %s' % (dnslib.QTYPE[r.rtype], r.rdata) for r in record.rr])

                if record.rr and record.rr[0].rtype == dnslib.QTYPE.CNAME:
                    hostname = str(record.rr[0].rdata)
                else:
                    break
            rfile.close()
            soc.close()
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())
            result = [repr(e), traceback.format_exc()]
        self.resultTextEdit.setPlainText('\n'.join(result))

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.isVisible():
            self.hide()
        self.resultTextEdit.clear()
        event.ignore()
