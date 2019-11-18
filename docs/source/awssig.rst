:mod:`awssig` -- Top-level AWS signature verification
==============================================================================

.. module:: awssig

The top-level awssig module automatically imports the following classes and
makes them available for export:

- :class:`exc.InvalidSignatureError`
- :class:`sigv4.AWSSigV4Verifier`
- :class:`sigv4.AWSSigV4S3Verifier`