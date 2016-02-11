AWS signature verification routines.
==============================================================================

This library provides signature verification for requests made to an AWS
service. Typically, this is used to provide mock interfaces for AWS services
or to rewrite AWS requests through a proxy host.

The current source tree can be found at <https://github.com/dacut/python-aws-sig>_.

.. todo:: Currently only `SigV4`_ is supported.

Contents:

.. toctree::
   :maxdepth: 2

   awssig
   exc
   sigv4

              
Example Usage
------------------------------------------------------------------------------

::

   >>> import awssig
   >>> access_key = "AKIDEXAMPLE"
   >>> secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
   >>> key_mapping = { access_key: secret_key }
   >>> v = awssig.AWSSigV4Verifier(
   ...     request_method="GET",
   ...     uri_path="/",
   ...     query_string="a=foo&b=foo",
   ...     headers={
   ...         "Date": "Mon, 09 Sep 2011 23:36:00 GMT",
   ...         "Host": "host.foo.com",
   ...         "Authorization": (
   ...             "AWS4-HMAC-SHA256 "
   ...             "Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, "
   ...             "SignedHeaders=date;host, "
   ...             "Signature=0dc122f3b28b831ab48ba65cb47300de53fbe91b577fe113edac383730254a3b"),
   ...    },
   ...    body=b"",
   ...    region="us-east-1",
   ...    service="host",
   ...    key_mapping=key_mapping,
   ...    timestamp_mismatch=None)
   >>> try:
   ...     v.verify()
   ...     print("ok")
   ... except awssig.InvalidSignatureError as e:
   ...     print("error: %s" % e)
   ok

Indices and tables
------------------------------------------------------------------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _SigV4: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
