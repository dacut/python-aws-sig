AWS signature verification routines.
==============================================================================

This library provides signature verification for requests made to an AWS
service. Typically, this is used to provide mock interfaces for AWS services
or to rewrite AWS requests through a proxy host.

The current source tree can be found on
`GitHub <https://github.com/dacut/python-aws-sig>`_.

Documentation is available at
`docs.ionosphere.io <https://docs.ionosphere.io/awssig/index.html>`_.

Currently only `SigV4`_ and `SigV4S3`_ (the S3 variant of SigV4) are supported.

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
   ...         "date": "Mon, 09 Sep 2011 23:36:00 GMT",
   ...         "host": "host.foo.com",
   ...         "authorization": (
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
   >>> v = awssig.AWSSigV4S3Verifier(
   ...     request_method="POST",
   ...     uri_path="/a//b/../c",
   ...     headers={
   ...         "date": "Mon, 09 Sep 2011 23:36:00 GMT",
   ...         "host": "host.foo.com",
   ...         "authorization": (
   ...             "AWS4-HMAC-SHA256 "
   ...             "Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, "
   ...             "SignedHeaders=date;host, "
   ...             "Signature=6b8af5a1e94a59c511e47267ab0cbfa1783dc42861ab7f09e0dba62680da8b28"),
   ...         "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
   ...    },
   ...    body=b"Hello world",
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


.. _SigV4: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
.. _SigV4S3: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
