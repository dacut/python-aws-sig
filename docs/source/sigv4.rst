:mod:`awssig.sigv4` --- AWS signature version 4
==============================================================================

.. module:: awssig.sigv4

This module provides support for verifying AWS calls made using the
`SigV4`_ algorithm.

Class :class:`AWSSigV4Verifier`
------------------------------------------------------------------------------

Verify an AWS SigV4 signature.

.. class:: AWSSigV4Verifier(request_method, uri_path, query_string, headers,
           body, region, service, key_mapping, timestamp_mismatch=60)

    Create a new AWSSigV4Verifier instance.

    :param str request_method: The HTTP method used to make the call.
        Typically "GET", "POST", "PUT", "DELETE", or "LIST".
    :param str uri_path: The path to the request. Typically "/", but might
        be a filesystem-style path ("/folder/subfolder/object") for S3-style
        requests.
    :param str query_string: Query parameters supplied to the call (the
        part after the '?'). This must be the empty string ("") if no query
        parameters were supplied.
    :param dict headers: A dictionary of string keys and values of the HTTP
        headers supplied in the request.
    :param bytes body: The request body. This must be an empty bytes object
        (b"") if no body was supplied (even for GET, DELETE, and LIST
        requests). Note that this *must* be a bytes object in Python 3.
    :param str region: The region the service is operating in (e.g.
        "us-east-1").
    :param str service: The name of the service being accessed.
    :param key_mapping: A dictionary-like object that provides secret
        keys given an access key.
    :param timestamp_mismatch: The allowable mismatch in the timestamp
        submitted for the request in seconds. If ``None``, timestamp checking
        is disabled.
    :type key_mapping: dict-like object
    :type timestamp_mismatch: int or None

    :raises TypeError: if request_method, uri_path, query_string, region, or
        service are not strings; body is not a string (Python 2) or
        bytes (Python 3); or headers is not a dict containg string keys and
        string values.
    
    .. method:: AWSSigV4Verifier.verify()
    
        Verifies that the request is properly signed.

        :return: ``True`` when the request is properly signed.
        :raises `awssig.exc.InvalidSignatureError`: if the request is not
            properly signed.

    .. attribute:: AWSSigV4Verifier.canonical_uri_path

        A string containing the canonical URI according to `RFC 3986`_.
        Redundant ("//") and relative ("/../", "/./") path components are
        removed.
    
    .. attribute:: AWSSigV4Verifier.query_parameters
              
        A dictionary of query parameter names to a list of the values seen.
    
    .. attribute:: AWSSigV4Verifier.canonical_query_string
    
        The canonicalized form of the query string as documented in
        `creating canonical requests`_. Note that the ``X-Amz-Signature``
        parameter (if provided) is removed from this string.
    
    .. attribute:: AWSSigV4Verifier.authorization_header_parameter
    
        The authorization header, either from the HTTP "Authorization" header.
        If this header is not present, is present multiple times, or does not
        begin with "AWS4-HMAC-SHA256", an ``AttributeError`` exception is
        raised.
    
    .. attribute:: AWSSigV4Verifier.signed_headers
    
        An ordered dictionary containing the header names and values used to
        sign the request.
    
    .. attribute:: AWSSigV4Verifier.request_date
    
        The date of the request in ISO8601 YYYYMMDD format.
    
        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an ``AttributeError``
        exception is raised.
    
    .. attribute:: AWSSigV4Verifier.request_timestamp
    
        The timestamp of the request in ISO8601 YYYYMMDD'T'HHMMSS'Z' format.
    
        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an ``AttributeError``
        exception is raised.
    
    .. attribute:: AWSSigV4Verifier.credential_scope
    
        The scope of the credentials to use.
    
        This is the request date, region, service, and the string
        "aws4_request" joined with slashes ('/').
    
    .. attribute:: AWSSigV4Verifier.access_key
    
        The access key used to sign the request.
    
        If the access key was not provided or is not in the same credential
        scope as this request, an ``AttributeError`` exception is raised.
    
    .. attribute:: AWSSigV4Verifier.request_signature
    
        The request signature passed in the request, either from the
        ``X-Amz-Signature`` query parameter or the ``Authorization`` HTTP
        header.
    
        If neither of these is present, an ``AttributeError`` exception is
        raised.
    
    .. attribute:: AWSSigV4Verifier.canonical_request
    
        The AWS SigV4 canonical request given parameters from an HTTP request,
        as described in the `creating canonical requests`_ document.
    
        If an attribute required to compute the canonical request is not
        present (:attr:`request_method`, :attr:`canonical_uri_path`,
        :attr:`canonical_query_string`, or :attr:`signed_headers`), an
        ``AttributeError`` exception is propagated.
    
    .. attribute:: AWSSigV4Verifier.string_to_sign
    
        The AWS SigV4 string being signed, as described in the
        `calculating the string to sign`_ document.
    
        If an attribute required to compute the string to sign is not present
        (:attr:`request_timestamp`, :attr:`credential_scope`, or
        :attr:`canonical_request`), an ``AttributeError`` exception is
        propagated.
    
    .. attribute:: AWSSigV4Verifier.expected_signature
    
        The AWS SigV4 signature expected from the request, as described in the
        `calculating the signature`_ document.
    
        If an attribute required to compute the signature is not present
        (:attr:`access_key`, :attr:`request_date`, :attr:`region`, or
        :attr:`service`), an ``AttributeError`` exception is propagated.
    
        If the corresponding secret key for the :attr:`access_key` is not
        found, a ``KeyError`` exception is propagated.

Utility Functions
------------------------------------------------------------------------------
        
.. function:: normalize_uri_path_component(path_component)

    Normalize the path component according to RFC 3986.  This performs the
    following operations:
    
    * Alpha, digit, and the symbols '-', '.', '_', and '~' (unreserved
      characters) are left alone.
    * Characters outside this range are percent-encoded.
    * Percent-encoded values are upper-cased ('%2a' becomes '%2A')
    * Percent-encoded values in the unreserved space (%41-%5A, %61-%7A,
      %30-%39, %2D, %2E, %5F, %7E) are converted to normal characters.

    If a percent encoding is incomplete, the percent is encoded as %25.

    :param str path_component: The path component to normalize.
    :return: the normalized path component
    :rtype: str
    :raises ValueError: if a percent encoding includes non-hex characters
        (e.g. %3z)

.. function:: get_canonical_uri_path(uri_path):

    Normalizes the specified URI path component, removing redundant slashes
    and relative path components.

    :param str uri_path: The URI path to normalize.
    :return: the normalized path component
    :rtype: str
    :raises ValueError: If any of the following occurs:
        * The URI path is not empty and not absolute (does not start with '/').
        * A parent relative path element ('..') attempts to go beyond the top.
        * An invalid percent-encoding is encountered.

.. function:: normalize_query_parameters(query_string):

    Converts a query string into a dictionary mapping parameter names to a
    list of the sorted values.  This ensurses that the query string follows
    % encoding rules according to RFC 3986 and checks for duplicate keys.

    :param str query_string: The query string to normalize.
    :return: the normalized query string
    :rtype: str
    :raises ValueError: if a percent encoding is invalid.
          
.. _SigV4: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
.. _RFC 3986: http://tools.ietf.org/html/rfc3986
.. _creating canonical requests: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
.. _calculating the string to sign: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
.. _calculating the signature: http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
