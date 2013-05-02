#!/usr/bin/env python

from distutils.core import setup

setup(
    name='WebDAV-Kerberos',
    version='0.2.0',
    description='Kerberised WebDAV client library',
    author='Bob Carroll',
    author_email='bob.carroll@alum.rit.edu',
    url='http://github.com/rcarz/WebDAV-Kerberos',
    py_modules=['krb5dav'],
    install_requires=['Python_WebDAV_Library', 'kerberos'],
)

