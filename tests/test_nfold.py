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

import array

from .context import keyutil
from keyutil.util.nfold import nfold
from nose.tools import assert_equals

def h(s):
    return array.array('B', s.decode('hex'))

def test_nfold():
    vectors = [
        [8, "012345", h('be072631276b1955')],
        [7, "password", h('78a07b6caf85fa')],
        [8, "Rough Consensus, and Running Code", h('bb6ed30870b7f0e0')],
        [21, "password", h('59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e')],
        [24, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY", h('db3b0d8f0b061e603282b308a50841229ad798fab9540c1b')],
        [21, "Q", h('518a54a215a8452a518a54a215a8452a518a54a215')],
        [21, "ba", h('fb25d531ae8974499f52fd92ea9857c4ba24cf297e')]
    ]

    import array
    for v in vectors:
        r = nfold(v[1], v[0])
        assert_equals(r, v[2])

