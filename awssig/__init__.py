#!/usr/bin/env python
"""
AWS signature verification.
"""

from __future__ import absolute_import
from .sigv4 import AWSSigV4Verifier, AWSSigV4S3Verifier, InvalidSignatureError

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
