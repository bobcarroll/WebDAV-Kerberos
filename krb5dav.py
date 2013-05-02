#!/usr/bin/env python2.7

# WebDAV-Kerberos - Kerberised WebDAV client library
# Copyright (c) 2013 Bob Carroll (bob.carroll@alum.rit.edu)
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import davlib
import kerberos
import Cookie

class Krb5Error(Exception):

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return 'Kerberos authentication failed with error: %s' % (self.message, )

class Krb5DAV(davlib.DAV):

    def __init__(self, *args, **kwargs):
        self.__spn = 'http@%s' % (args[0], )
        self.__upn = kwargs.pop('principal') if 'principal' in kwargs else ''
        self.__spnego = False
        self.__cookies = Cookie.SimpleCookie()
        self.__persistauth = False
        apply(davlib.DAV.__init__, (self, ) + args, kwargs)

    def __probe_mechanisms(self):
        if not self.__spnego:
            response = davlib.DAV._request(self, 'OPTIONS', '/')
            authstr = response.getheader('www-authenticate')
            mechs = [s.strip() for s in authstr.split(',')]
            self.__spnego = 'Negotiate' in mechs
            self.close()

        if not self.__spnego:
            raise Krb5Error('Server does not support Kerberos authentication')

    def __challenge(self, gssctx, blob):
        try:
            result = kerberos.authGSSClientStep(gssctx, blob)
        except kerberos.GSSError as ex:
            raise Krb5Error('%s (%s)' % (ex[0][0], ex[1][0]))
        except kerberos.KrbError as ex:
            raise Krb5Error(ex[0])

        if result == kerberos.AUTH_GSS_COMPLETE:
            return (True, '')

        try:
            response = kerberos.authGSSClientResponse(gssctx)
        except kerberos.GSSError as ex:
            raise Krb5Error('%s (%s)' % (ex[0][0], ex[1][0]))
        except kerberos.KrbError as ex:
            raise Krb5Error(ex[0])

        return (False, response)

    def __store_cookies(self, response):
        cookiestr = response.getheader('set-cookie')

        if not cookiestr is None:
            self.__cookies.load(cookiestr)

    def __request_authenticate(self, method, url, body, extra_hdrs):
        self.__probe_mechanisms()

        try:
            result, gssctx = kerberos.authGSSClientInit(self.__spn, principal=self.__upn)
        except kerberos.GSSError as ex:
            raise Krb5Error('%s (%s)' % (ex[0][0], ex[1][0]))
            
        response = None
        blob = ''

        while True:
            try:
                result, blob = self.__challenge(gssctx, blob)
            except Krb5Error as ex:
                kerberos.authGSSClientClean(gssctx)
                raise ex

            if result:
                self.__upn = kerberos.authGSSClientUserName(gssctx)
                break

            self.close()
            extra_hdrs['Authorization'] = 'Negotiate %s' % (blob, )
            response =  davlib.DAV._request(self, method, url, body, extra_hdrs)

            self.__store_cookies(response)
            authstr = response.getheader('www-authenticate')
            (mech, blob) = authstr.split(' ')

            persistauth = response.getheader('persistent-auth')
            self.__persistauth = persistauth == 'true'

        kerberos.authGSSClientClean(gssctx)
        return response

    def _request(self, method, url, body=None, extra_hdrs={}):
        cookies = Cookie.SimpleCookie()
        cookies.load(', '.join([self.__cookies[c].OutputString() for c in self.__cookies]))

        if 'Cookie' in extra_hdrs:
            cookies.load(extra_hdrs['Cookie'])

        if len(cookies) > 0:
            extra_hdrs['Cookie'] = ', '.join(['%s=%s' % (c, cookies[c].value) for c in cookies])

        if self.__persistauth:
            return davlib.DAV._request(self, method, url, body, extra_hdrs)
        else:
            return self.__request_authenticate(method, url, body, extra_hdrs)

    def whoami(self):
        return self.__upn

