
import time

from PyQt5 import QtWidgets, QtCore

from hxcrypto import ECC
from hxcrypto.util import key_to_bytes, encrypt, decrypt

from .ui_crypto import Ui_Crypto


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_Crypto()
        self.ui.setupUi(self)

        self.__ecckey = None

        self.__key = None
        self.other_key = None
        self._last_active = time.time()

        self.ui.textEdit.setWordWrapMode(3)
        self.ui.psktextEdit.setWordWrapMode(3)

        self.ui.pubkeyButton.clicked.connect(self.copy_pubkey)
        self.ui.otherKeyEdit.editingFinished.connect(self.exchange_edit)

        self.ui.encryptButton.clicked.connect(self.encrypt)
        self.ui.decryptButton.clicked.connect(self.decrypt)
        self.ui.resetPrivateButton.clicked.connect(self.resetPrivate)
        self.ui.resetExchangeButton.clicked.connect(self.resetExchange)
        self.ui.decryptButton.clicked.connect(self.decrypt)

        self.ui.PSKencryptButton.clicked.connect(self.pskencrypt)
        self.ui.PSKdecryptButton.clicked.connect(self.pskdecrypt)

        self.resetPrivate()
        self.show()

    def resetPrivate(self):
        self.__key = None
        self.__ecckey = ECC(256)
        pubk_hash = ECC.b64u_to_hash(self.get_pubkey_b64u())
        _tr = QtCore.QCoreApplication.translate
        self.ui.pubkeyButton.setText(_tr('Crypto', 'Copy Public Key') + ' - ' + pubk_hash)
        if self.other_key:
            self.exchange(self.other_key)

    def get_pubkey_b64u(self):
        return self.__ecckey.get_pub_key_b64u()

    def copy_pubkey(self):
        public_key = self.get_pubkey_b64u()
        app = QtWidgets.QApplication.instance()
        cb = app.clipboard()
        cb.setText(public_key)

    def resetExchange(self):
        self.__key = None
        self.other_key = None
        self.ui.otherKeyEdit.setText("")
        self.ui.otherKeyEdit.setReadOnly(False)

    def exchange(self, otherkey):
        self.__key = self.__ecckey.get_dh_key_b64u(otherkey)

    def exchange_edit(self):
        if self.ui.otherKeyEdit.isReadOnly():
            return
        otherkey = self.ui.otherKeyEdit.text()
        if otherkey:
            try:
                self.exchange(otherkey)
            except Exception as err:
                self.statusBar().showMessage(repr(err), 5000)
            else:
                self.other_key = otherkey
                pubk_hash = ECC.b64u_to_hash(otherkey)
                self.ui.otherKeyEdit.setText(pubk_hash)
                self.ui.otherKeyEdit.setReadOnly(True)

    def encrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        if not self.__key:
            self.statusBar().showMessage("key exchange not finished", 5000)
            return

        plain_text = self.ui.textEdit.toPlainText()
        if not plain_text:
            return
        try:
            cipher_text = encrypt(self.__key, plain_text)
        except Exception as err:
            self.statusBar().showMessage(repr(err), 5000)
            return

        self.ui.textEdit.setPlainText(cipher_text)

        self._last_active = time.time()

    def decrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        if not self.__key:
            self.statusBar().showMessage("key exchange not finished", 5000)
            return

        cipher_text = self.ui.textEdit.toPlainText()
        if not cipher_text:
            return

        try:
            plain_text = decrypt(self.__key, cipher_text)
            if not plain_text:
                return
            self.ui.textEdit.setPlainText(plain_text)
        except Exception as err:
            self.statusBar().showMessage(repr(err), 5000)
            return

        self._last_active = time.time()

    def pskencrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        plain_text = self.ui.psktextEdit.toPlainText()
        if not plain_text:
            return

        key = self.ui.pskEdit.text()
        key = key_to_bytes(key)

        try:
            cipher_text = encrypt(key, plain_text)
            if not cipher_text:
                return
        except Exception as err:
            self.statusBar().showMessage(repr(err), 5000)
            return

        self.ui.psktextEdit.setPlainText(cipher_text)

        self._last_active = time.time()

    def pskdecrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        cipher_text = self.ui.psktextEdit.toPlainText()
        if not cipher_text:
            return

        key = self.ui.pskEdit.text()
        key = key_to_bytes(key)

        try:
            plain_text = decrypt(key, cipher_text)
            if not plain_text:
                return
            self.ui.psktextEdit.setPlainText(plain_text)
        except Exception as err:
            self.statusBar().showMessage(repr(err), 5000)
            return

        self._last_active = time.time()
