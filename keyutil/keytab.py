#!/usr/bin/env python
# Copyright (c) 2015, Nate Rosenblum
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

import argparse
import derive
import getpass
import struct
import time

# http://www.ioplex.com/utilities/keytab.txt is helpful
class Keytab:
    """ Keytab generator """

    def __init__(self):
        self.keytypes = {
                'des-cbc-md5':                  0x0003,
                'aes128-cts-hmac-sha1-96':      0x0011,
                'rc4-hmac-md5':                 0x0017,
            }
        self.entries = []

    class Entry:
        def __init__(self, principal, realm, kvno, encoding, components, key):
            self.principal = principal
            self.realm = realm
            self.kvno = kvno
            self.encoding = encoding
            self.components = components
            self.key = key

    def add_entry(self, princ, kvno, keytype, password):
        if keytype == 'rc4-hmac-md5':
            keybytes = derive.derive_password_rc4hmac(password)
        else:
            raise ValueError, "Unsupported key type {}".format(keytype)

        encoding = self.keytypes[keytype]
        [principal, realm] = princ.split('@')
        components = principal.split('/')
        self.entries.append(self.Entry(principal, realm, kvno, encoding,
            components, keybytes))

    @staticmethod
    def serialize_string(value):
        fmt = "!H{}s".format(len(value))
        return struct.pack(fmt, len(value), value)

    @staticmethod
    def serialize_bytearray(value):
        ret = bytearray()
        ret.extend(struct.pack('!H', len(value)))
        for b in value:
            ret.extend(struct.pack('!B', b))
        return ret

    def serialize(self, value):
        if isinstance(value, str):
            return self.serialize_string(value)
        elif isinstance(value, bytearray):
            return self.serialize_bytearray(value)
        else:
            raise(ValueError)

    def serialize_keytab(self):
        output = bytearray()

        # Version is fixed
        output += struct.pack('!H', 0x502)

        for entry in self.entries:
            ser = bytearray();

            # num_components
            ser += struct.pack('!H', len(entry.components))
            # realm
            ser += self.serialize(entry.realm)
            # Name components
            for component in entry.components:
                ser += self.serialize(component)
            # Always KRB5_NT_PRINCIPAL
            ser += struct.pack('!L', 1)
            # Whatever. Right now.
            ser += struct.pack('!L', int(time.time()))
            # Kvno. XXX may overflow
            ser += struct.pack('!B', entry.kvno)
            # Key encoding
            ser += struct.pack('!H', entry.encoding)
            # Key
            ser += self.serialize(entry.key);

            output += struct.pack('!l', len(ser))
            output += ser

        return output

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("principal", metavar='principal', type=str, nargs=1,
            help='Principal name (name@realm)')
    parser.add_argument("--kvno", dest="kvno", action="store", default=1,
            help='Key version number (default 1)')
    parser.add_argument("--password", dest="password", action="store",
            default=None, help='Password agument (default is to prompt)')
    parser.add_argument("-o", "--output", dest="output", action="store",
            default="keytab", help='Output keytab file name')
    options = parser.parse_args()

    if not options.password:
        options.password = getpass.getpass("Password")

    kt = Keytab()
    kt.add_entry(options.principal[0], options.kvno, "rc4-hmac-md5",
            options.password)
    ktbytes = kt.serialize_keytab()

    with open(options.output, 'wb') as out:
        out.write(ktbytes)

if __name__ == "__main__":
    main()
