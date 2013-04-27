#!/usr/bin/env python

from distutils.core import setup

setup(
    name='WebDAV-Kerberos',
    version='0.1.0',
    description='Kerberised WebDAV client library',
    author='Bob Carroll',
    author_email='bob.carroll@alum.rit.edu',
    url='http://github.com/rcarz/WebDAV-Kerberos',
    py_modules=['krb5dav'],
    requires=['Python_WebDAV_Library', 'PyKerberos'],
)

