#!/usr/bin/env python
# Copyright (c) 2014, Nate Rosenblum
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

from array import array
from fractions import gcd

def nfold(instr, n):
    """ The n-fold key stretching algorithm
        Defined by:

        Blumenthal, U. and S. Bellovin, "A Better Key Schedule for DES-Like
        Ciphers", Proceedings of PRAGOCRYPT '96, 1996.

        Test vectors are from RFC 3961.
    """

    def lcm(n1, n2):
        """ Least common multiple """
        return (n1 * n2) // gcd(n1, n2)

    # Work with binary arrays rather than strings
    ina = array('B', instr)

    def rot13(a):
        """ Rotate a byte array 13 bits right """
        ret = array('B')

        if len(a) == 1:
            # Special case rotation of a single byte
            b = (a[0] >> 5 & 0x7) | ((a[0] << 3) & 0xff)
            ret.append(b)
            return ret

        # This is enormously inefficient, but our objective is clarity
        b = 0
        for i in range(0, len(a)):
            # Each output byte b_i is computed as
            #
            #     b_{i-1} >> 5 | b_{i-2} << 3
            #
            # (appropriately masked, of course)
            ret.append(((a[i - 1] >> 5) & 0x7) | ((a[i - 2] << 3) & 0xff))
        return ret

    def ocadd(v1, v2):
        """ One's complement addition over n-byte big endian values"""
        assert len(v1) == len(v2)
        n = len(v1)
        ret = array('B', [0] * n)
        carry = 0
        for i in range(0, n):
            b = v1[n - 1 - i] + v2[n - 1 - i] + carry
            ret[n - 1 - i] = b & 0xFF
            carry = 1 if b >> 8 else 0
        # Add back the carry bit
        if carry:
            for i in range(0, n):
                b = ret[n - 1 - i]
                if b < 0xFF:
                    ret[n - 1 - i] += 1
                    break
                else:
                    ret[n - 1 - i] = 0
        return ret

    leastmult = lcm(len(instr), n)

    # Replicate the input to the LCM length, rotating 13 bits right on
    # each iteration
    extended = array('B')
    extended.extend(ina)
    work = ina
    for i in range(0, leastmult / len(ina)):
        work = rot13(work)
        extended.extend(work)

    # Compute one's complement addition over the extended string, treating
    # it as a sequence of n-bit big-endian numbers
    result = array('B', [0] * n)
    for i in range(0, leastmult / n):
        result = ocadd(result, extended[n * i : n * i + n])

    return result
