# -*- coding: utf-8 -*-
import locale
import importlib

try:
    lang = importlib.import_module('.lang.%s' % locale.getdefaultlocale()[0], __package__)
except Exception:
    lang = importlib.import_module('.lang.en_US', __package__)


def translate(location, string):
    try:
        return lang.data[string]
    except KeyError:
        return string
