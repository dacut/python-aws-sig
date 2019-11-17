#!/usr/bin/env python
"""
AWS signature verification exceptions.
"""

class InvalidSignatureError(Exception):
    """
    An exception indicating that the signature on the request was invalid.
    """
    pass

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
