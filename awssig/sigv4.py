"""
SigV4 authentication routines.
"""

from __future__ import absolute_import
from collections import OrderedDict
from datetime import datetime, timedelta
from hashlib import sha256
import hmac
from logging import getLogger
from os.path import basename, split as path_split, splitext
from re import compile as re_compile
from string import ascii_letters, digits
from traceback import extract_stack
from warnings import warn

from six import (
    BytesIO, binary_type, indexbytes, int2byte, iterbytes, iteritems,
    iterkeys, string_types)
from six.moves.urllib.parse import unquote as url_unquote # pylint: disable=E0401
from pytz import UTC
from .dateutil import parse_iso8601, parse_rfc2282
from .exc import InvalidSignatureError

# pylint: disable=C0103

# Algorithm for AWS SigV4
AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256"

# Unreserved bytes from RFC 3986.
_rfc3986_unreserved = set(iterbytes((ascii_letters + digits + "-._~")
                                    .encode("utf-8")))

# ASCII code for '%'
_ascii_percent = ord(b"%")

# ASCII code for '+'
_ascii_plus = ord(b"+")

# Header and query string keys
_application_x_www_form_urlencoded = "application/x-www-form-urlencoded"
_authorization = "authorization"
_aws4_request = "aws4_request"
_aws4_request_bytes = _aws4_request.encode("utf-8")
_charset = "charset"
_content_type = "content-type"
_credential = "Credential"
_date = "date"
_signature = "Signature"
_signedheaders = "SignedHeaders"
_streaming_aws4_hmac_sha256_payload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
_unsigned_payload = "UNSIGNED-PAYLOAD"
_x_amz_algorithm = "X-Amz-Algorithm"
_x_amz_content_sha256 = "x-amz-content-sha256"
_x_amz_credential = "X-Amz-Credential"
_x_amz_date = "X-Amz-Date"
_x_amz_date_lower = "x-amz-date"
_x_amz_security_token = "X-Amz-Security-Token"
_x_amz_security_token_lower = "x-amz-security-token"
_x_amz_signature = "X-Amz-Signature"
_x_amz_signedheaders = "X-Amz-SignedHeaders"

# SHA-256 hex-digest regex
_sha256_regex = re_compile(r"^[0-9a-f]{64}$")

# SHA-256 digest of an empty string
_sha256_empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Match for multiple slashes
_multislash = re_compile(r"//+")

# Match for multiple spaces
_multispace = re_compile(r"  +")

# Logging instance
log = getLogger("awssig.sigv4")

class AWSSigV4Verifier(object):
    # pylint: disable=R0902,R0904
    """
    Verify that a query matches the expectations of AWS SigV4.
    """

    def __init__(self, **kw):
        """
        AWSSigV4Verifier(
            request_method: str,
            uri_path: str,
            query_string: str,
            headers: Dict[str, Iterable[str]],
            body: bytes,
            region: str,
            service: str,
            key_mapping: Callable[[str, Optional[str]], Optional[str]],
            timestamp_mismatch: int=60)

        Create a new AWSSigV4Verifier instance. Properties can be specified
        as keyword arguments.

        request_method: The HTTP request method (GET, PUT, POST, etc.).
        uri_path: The path accessed (usually just "/").
        query_string: The query string portion of the URI.
        headers: A dictionary mapping HTTP headers to their values.
        body: The request body (if any). This should be undecoded (bytes, not
            a Unicode str)
        region: The AWS region (or pseudo-region) the service is running in.
        service: The name of the service being authorized against.
        kep_mapping: A callable object that will be invoked to return a
            secret key. This will be invoked with one or two arguments.

            If only an access key is specified, it will be invoked as:
                key_mapping(aws_access_key_id=access_key)

            If an access key and token are specified, it will be invoked as:
                key_mapping(aws_access_key_id=access_key,
                            aws_session_token=token)

            The return value is either a string specifying the corresponding
            secret key or None to indicate the access key is invalid.
        """
        super(AWSSigV4Verifier, self).__init__()
        self._request_method = "GET"
        self._uri_path = "/"
        self._query_string = ""
        self._body = b""
        self._region = "us-east-1"
        self._service = "none"
        self._key_mapping = lambda *args: None
        self._headers = {}
        self._timestamp_mismatch = 60

        for key, value in kw.items():
            setattr(self, key, value)
        return

    @property
    def request_method(self):
        """
        The HTTP method (GET, POST, PUT) used to make the request.
        """
        return self._request_method

    @request_method.setter
    def request_method(self, value):
        if not isinstance(value, string_types):
            raise TypeError("Expected request_method to be a string.")

        self._request_method = value
        return

    @property
    def uri_path(self):
        """
        The path component of the URI.
        """
        return self._uri_path

    @uri_path.setter
    def uri_path(self, value):
        if not isinstance(value, string_types):
            raise TypeError("Expected uri_path to be a string.")

        self._uri_path = value
        return

    @property
    def query_string(self):
        """
        The query string portion of the URI.
        """
        return self._query_string

    @query_string.setter
    def query_string(self, value):
        if not isinstance(value, string_types):
            raise TypeError("Expected query_string to be a string.")

        self._query_string = value
        return

    @property
    def body(self):
        """
        The body sent with the HTTP request (for PUT and POST requests).
        """
        return self._body

    @body.setter
    def body(self, value):
        if not isinstance(value, binary_type):
            raise TypeError("Expected body to be a byte array.")

        self._body = value
        return

    @property
    def region(self):
        """
        The region the service is running in.
        """
        return self._region

    @region.setter
    def region(self, value):
        if not isinstance(value, string_types):
            raise TypeError("Expected region to be a string.")

        self._region = value
        return

    @property
    def service(self):
        """
        The name of the service being invoked.
        """
        return self._service

    @service.setter
    def service(self, value):
        if not isinstance(value, string_types):
            raise TypeError("Expected service to be a string.")

        self._service = value
        return

    @property
    def key_mapping(self):
        """
        A function that converts an AWS access key and, optionally, an AWS
        token, and returns the corresponding secret key (or None if the
        access key or token are invalid).
        """
        return self._key_mapping

    @key_mapping.setter
    def key_mapping(self, value):
        self._key_mapping = value
        return

    @property
    def headers(self):
        """
        The HTTP headers sent with the request
        """
        return self._headers

    @headers.setter
    def headers(self, value):
        if not isinstance(value, dict):
            raise TypeError("Expected headers to be a dict.")

        new_headers = {}

        for key, header_values in iteritems(value):
            if not isinstance(key, string_types):
                raise TypeError("Header must be a string: %r" % (key,))

            if isinstance(header_values, string_types):
                depth = _get_callee_depth()

                warn(
                    "Header %r value must be an iterable of strings: %r" %
                    (key, type(header_values).__name__),
                    category=DeprecationWarning, stacklevel=depth)
                new_headers[key] = [header_values]
            else:
                values = []
                try:
                    hv_iter = iter(header_values)
                except TypeError:
                    raise TypeError(
                        "Header %r value must be an iterable of strings: %r" %
                        (key, type(header_values).__name__))
                for i, el in enumerate(hv_iter):
                    if not isinstance(el, string_types):
                        raise TypeError(
                            "Header %r value %d must be a string: %r" %
                            (key, i, type(el).__name__))
                    values.append(el)
                new_headers[key] = values

        self._headers = new_headers

    @property
    def content_type(self):
        """
        A 2-tuple containing the content type and charset of the request body,
        or None if the content type was not specified.
        """
        content_type_values = self.headers.get(_content_type)
        if not content_type_values:
            return None

        if len(content_type_values) > 1:
            raise ValueError("Multiple values for Content-Type header")

        parts = content_type_values[0].split(";")
        content_type = parts[0]

        for param_str in parts[1:]:
            param_str = param_str.strip()
            param_parts = param_str.split("=", 1)
            if not(param_parts) or len(param_parts) < 2:
                continue

            param_name = param_parts[0].lower()
            if param_name == _charset:
                charset = param_parts[1]
                break
        else:
            charset = "utf-8"

        return content_type, charset

    @property
    def timestamp_mismatch(self):
        """
        The allowable mismatch in the timestamp, in seconds.
        """
        return self._timestamp_mismatch

    @timestamp_mismatch.setter
    def timestamp_mismatch(self, value):
        if value is not None:
            if not isinstance(value, (int, float)):
                raise TypeError("Expected timestamp_mismatch to be a number.")

            if value < 0:
                raise ValueError("timestamp_mismatch cannot be negative.")

        self._timestamp_mismatch = value
        return

    @property
    def canonical_uri_path(self):
        """
        The canonicalized URI path from the request.
        """
        return get_canonical_uri_path(self.uri_path)

    @property
    def query_parameters(self):
        """
        A key to list of values mapping of the query parameters seen in the
        request.
        """
        return normalize_query_parameters(self.query_string)

    @property
    def canonical_query_string(self):
        """
        The canonical query string from the query parameters.

        This takes the query string from the request and orders the parameters
        into a string. If the body is of type application/x-www-form-urlencoded,
        it is included as part of the content string.
        """
        results = []
        for key, values in iteritems(self.query_parameters):
            # Don't include the signature itself.
            if key == _x_amz_signature:
                continue

            for value in values:
                results.append("%s=%s" % (key, value))
        
        ct_info = self.content_type
        if ct_info and ct_info[0] == _application_x_www_form_urlencoded:
            # Body is a form; include its parts in our result
            charset = ct_info[1]
            for key, values in iteritems(normalize_query_parameters(
                    self.body.decode(charset))):
                for value in values:
                    results.append("%s=%s" % (key, value))

        return "&".join(sorted(results))

    @property
    def authorization_header_parameters(self):
        """
        The parameters from the Authorization header (only).  If the
        Authorization header is not present or is not an AWS SigV4 header, an
        AttributeError exception is raised.
        """
        auth_values = self.headers.get(_authorization)
        if auth_values is None:
            raise AttributeError("Authorization header is not present")

        if len(auth_values) > 1:
            raise ValueError("Multiple Authorization headers present")

        auth = auth_values[0]

        if not auth.startswith(AWS4_HMAC_SHA256 + " "):
            raise AttributeError("Authorization header is not AWS SigV4")

        result = {}
        for parameter in auth[len(AWS4_HMAC_SHA256)+1:].split(","):
            parameter = parameter.strip()
            try:
                key, value = parameter.split("=", 1)
            except ValueError:
                raise AttributeError(
                    "Invalid Authorization header: missing '='")

            if key in result:
                raise AttributeError(
                    "Invalid Authorization header: duplicate key %r" % key)

            result[key] = value
        return result

    @property
    def signed_headers(self):
        """
        An ordered dictionary containing the signed header names and values.
        """
        # See if the signed headers are listed in the query string
        signed_headers = self.query_parameters.get(_x_amz_signedheaders)
        if signed_headers is not None:
            signed_headers = url_unquote(signed_headers[0])
        else:
            # Get this from the authentication header
            signed_headers = self.authorization_header_parameters[
                _signedheaders]

        # Header names are separated by semicolons.
        parts = signed_headers.split(";")

        # Make sure the signed headers list is canonicalized.  For security
        # reasons, we consider it an error if it isn't.
        canonicalized = sorted([sh.lower() for sh in parts])
        if parts != canonicalized:
            raise AttributeError("SignedHeaders is not canonicalized: %r" %
                                 (signed_headers,))

        # Allow iteration in-order. Replace multiple spaces in header values
        # with single spaces.
        return OrderedDict([
            (header, ",".join(
                [_multispace.sub(" ", v) for v in self.headers[header]]))
            for header in signed_headers.split(";")])

    @property
    def request_date_utc(self):
        """
        The UTC date of the request in ISO8601 YYYYMMDD format.

        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an AttributeError exception
        is raised.
        """
        return self.request_timestamp.astimezone(UTC).strftime("%Y%m%d")

    @property
    def request_timestamp(self):
        """
        The timestamp of the request as a Timestamp.

        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an AttributeError exception
        is raised.
        """
        amz_date_values = self.query_parameters.get(_x_amz_date)
        if amz_date_values is not None:
            if len(amz_date_values) > 1:
                raise ValueError(
                    "Multiple X-Amz-Date query parameters present")
        else:
            amz_date_values = self.headers.get(_x_amz_date_lower)
            if amz_date_values is not None:
                if len(amz_date_values) > 1:
                    raise ValueError(
                        "Multiple X-Amz-Date header values present")
            else:
                amz_date_values = self.headers.get(_date)
                if amz_date_values is None:
                    raise AttributeError("Date was not passed in the request")
                elif len(amz_date_values) > 1:
                    raise ValueError(
                        "Multiple Date header values present")

        date_str = amz_date_values[0]
        date = parse_iso8601(date_str)
        if not date:
            date = parse_rfc2282(date_str)
        if not date:
            raise AttributeError(
                "Date is not a valid ISO 8601 or RFC 2282 string: %r" %
                date_str)

        return date

    @property
    def credential_scope(self):
        """
        The scope of the credentials to use.
        """
        return (self.request_date_utc + "/" + self.region + "/" + self.service +
                "/" + _aws4_request)

    @property
    def access_key(self):
        """
        The access key id used to sign the request.

        If the access key is not in the same credential scope as this request,
        an AttributeError exception is raised.
        """
        credential = self.query_parameters.get(_x_amz_credential)
        if credential is not None:
            credential = url_unquote(credential[0])
        else:
            credential = self.authorization_header_parameters.get(_credential)

            if credential is None:
                raise AttributeError("Credential was not passed in the request")
        try:
            key, scope = credential.split("/", 1)
        except ValueError:
            raise AttributeError("Invalid request credential: %r" % credential)

        if scope != self.credential_scope:
            raise AttributeError("Incorrect credential scope: %r (wanted %r)" %
                                 (scope, self.credential_scope))

        return key

    @property
    def session_token(self):
        """
        The session token passed with the request, or None if a session token
        was not specified.
        """
        session_token_values = self.query_parameters.get(_x_amz_security_token)
        if session_token_values:
            if len(session_token_values) > 1:
                raise ValueError(
                    "Multiple X-Amz-Security-Token query parameters provided")
        else:
            session_token_values = self.headers.get(_x_amz_security_token_lower)
            if not session_token_values:
                return None
            if len(session_token_values) > 1:
                raise ValueError(
                    "Multiple X-Amz-Security-Token headers provided")
        
        return session_token_values[0]

    @property
    def request_signature(self):
        """
        The signature passed in the request.
        """
        signature = self.query_parameters.get(_x_amz_signature)
        if signature is not None:
            signature = signature[0]
        else:
            signature = self.authorization_header_parameters.get(_signature)
            if signature is None:
                raise AttributeError("Signature was not passed in the request")

        return signature

    @property
    def canonical_request(self):
        """
        The AWS SigV4 canonical request given parameters from an HTTP request.
        This process is outlined here:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        The canonical request is:
            request_method + '\n' +
            canonical_uri_path + '\n' +
            canonical_query_string + '\n' +
            signed_headers + '\n' +
            sha256(body).hexdigest()
        """
        signed_headers = self.signed_headers
        header_lines = "".join(
            ["%s:%s\n" % item for item in iteritems(signed_headers)])
        header_keys = ";".join([key for key in iterkeys(self.signed_headers)])

        ct_info = self.content_type
        if ct_info and ct_info[0] == _application_x_www_form_urlencoded:
            body_digest = _sha256_empty_digest
        else:
            body_digest = sha256(self.body).hexdigest()

        return (self.request_method + "\n" +
                self.canonical_uri_path + "\n" +
                self.canonical_query_string + "\n" +
                header_lines + "\n" +
                header_keys + "\n" +
                body_digest)

    @property
    def string_to_sign(self):
        """
        The AWS SigV4 string being signed.
        """
        timestamp_str = (
            self.request_timestamp.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ"))

        return (AWS4_HMAC_SHA256 + "\n" +
                timestamp_str + "\n" +
                self.credential_scope + "\n" +
                sha256(self.canonical_request.encode("utf-8")).hexdigest())

    @property
    def expected_signature(self):
        """
        The AWS SigV4 signature expected from the request.
        """
        session_token = self.session_token
        try:
            if session_token:
                secret_key = self.key_mapping(self.access_key, session_token)
            else:
                secret_key = self.key_mapping(self.access_key)
        except TypeError as e:
            if "is not callable" not in str(e):
                raise
            
            # Old docs specify that we call this using __getitem__ (sigh)
            if session_token:
                secret_key = self.key_mapping[(self.access_key, session_token)]
            else:
                secret_key = self.key_mapping[self.access_key]

            warn("key_mapping needs to be updated to be a callable object",
                 DeprecationWarning, _get_callee_depth())

        k_secret = b"AWS4" + secret_key.encode("utf-8")
        k_date = hmac.new(k_secret, self.request_date_utc.encode("utf-8"),
                          sha256).digest()
        k_region = hmac.new(k_date, self.region.encode("utf-8"),
                            sha256).digest()
        k_service = hmac.new(k_region, self.service.encode("utf-8"),
                             sha256).digest()
        k_signing = hmac.new(k_service, _aws4_request_bytes, sha256).digest()

        return hmac.new(k_signing, self.string_to_sign.encode("utf-8"),
                        sha256).hexdigest()

    def verify(self):
        """
        Verifies that the request timestamp is not beyond our allowable
        timestamp mismatch and that the request signature matches our
        expectations.
        """
        try:
            if self.timestamp_mismatch is not None:
                req_ts = self.request_timestamp.astimezone(UTC)
                mm_td = timedelta(seconds=self.timestamp_mismatch)
                now = datetime.now(UTC)
                min_ts = now - mm_td
                max_ts = now + mm_td

                if not (min_ts <= req_ts <= max_ts):
                    raise InvalidSignatureError(
                        "Timestamp mismatch: request timestamp %s outside of "
                        "allowed range %s to %s" % (req_ts, min_ts, max_ts))

            if self.expected_signature != self.request_signature:
                raise InvalidSignatureError(
                    "Signature mismatch: expected %r, got %r" % (
                        self.expected_signature, self.request_signature))
        except (AttributeError, KeyError, ValueError) as e:
            raise InvalidSignatureError(str(e))

        return True

class AWSSigV4S3Verifier(AWSSigV4Verifier):
    """
    Variant of AWS SigV4 for S3-style authentication.

    Compared to regular SigV4, SigV4S3 has the following differences:
    
    1. Consecutive slashes in URI paths are preserved: "/a//b" is a distinct
       object from "/a/b".
    2. The "x-amz-content-sha256" header must be present and set to either
       the SHA-256 checksum of the content (uploaded in a single chunk),
       UNSIGNED-PAYLOAD, or STREAMING-AWS4-HMAC-SHA256-PAYLOAD.
    """
    @property
    def canonical_uri_path(self):
        """
        The canonicalized URI path from the request.

        This is similar to the SigV4 canonicalized URI path, but with multiple
        slashes and dots preserved.
        """
        if self.uri_path == "":
            return "/"

        if not self.uri_path.startswith("/"):
            raise ValueError("URI path is not absolute.")

        # Do *not* handle ., .., etc; these are valid in S3 URLs.
        return "/".join(
            [normalize_uri_path_component(el)
             for el in self.uri_path.split("/")])

    @property
    def canonical_query_string(self):
        """
        The canonical query string from the query parameters.

        This takes the query string from the request and orders the parameters
        into a string. The body is always ignored for S3 requests.
        """
        results = []
        for key, values in iteritems(self.query_parameters):
            # Don't include the signature itself.
            if key == _x_amz_signature:
                continue

            for value in values:
                results.append("%s=%s" % (key, value))

        return "&".join(sorted(results))

    @property
    def canonical_request(self):
        """
        The AWS SigV4S3 canonical request given parameters from an HTTP request.
        This is similar to the standard AWS SigV4 canonical request, but allows
        for the replacement of the final sha256(body).hexdigest() line with
        either 'UNSIGNED-PAYLOAD' or 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
        depending on the value of the (required) x-amz-content-sha256 header.
        """
        content_sha256_values = self.headers.get(_x_amz_content_sha256)
        if not content_sha256_values:
            raise AttributeError(
                "x-amz-content-sha256 header was not passed in the request")

        if len(content_sha256_values) > 1:
            raise ValueError(
                "Multiple x-amz-content-sha256 headers present")
        
        content_sha256 = content_sha256_values[0]

        if (content_sha256 not in (
                _streaming_aws4_hmac_sha256_payload, _unsigned_payload)
                and not _sha256_regex.match(content_sha256)):
            raise ValueError(
                "Invalid value for x-amz-content-sha256 header: %r" %
                (content_sha256))
        
        signed_headers = self.signed_headers
        header_lines = "".join(
            ["%s:%s\n" % item for item in iteritems(signed_headers)])
        header_keys = ";".join([key for key in iterkeys(self.signed_headers)])

        return (self.request_method + "\n" +
                self.canonical_uri_path + "\n" +
                self.canonical_query_string + "\n" +
                header_lines + "\n" +
                header_keys + "\n" +
                content_sha256)    

def normalize_uri_path_component(path_component):
    """
    normalize_uri_path_component(path_component) -> str

    Normalize the path component according to RFC 3986.  This performs the
    following operations:
    * Alpha, digit, and the symbols '-', '.', '_', and '~' (unreserved
      characters) are left alone.
    * Characters outside this range are percent-encoded.
    * Percent-encoded values are upper-cased ('%2a' becomes '%2A')
    * Percent-encoded values in the unreserved space (%41-%5A, %61-%7A,
      %30-%39, %2D, %2E, %5F, %7E) are converted to normal characters.

    If a percent encoding is incomplete, the percent is encoded as %25.

    A ValueError exception is thrown if a percent encoding includes non-hex
    characters (e.g. %3z).
    """
    result = BytesIO()

    i = 0
    path_component = path_component.encode("utf-8")
    while i < len(path_component):
        c = indexbytes(path_component, i)
        if c in _rfc3986_unreserved:
            result.write(int2byte(c))
            i += 1
        elif c == _ascii_percent: # percent, '%', 0x25, 37
            if i + 2 >= len(path_component):
                result.write(b"%25")
                i += 1
                continue
            try:
                value = int(path_component[i+1:i+3], 16)
            except ValueError:
                raise ValueError("Invalid %% encoding at position %d" % i)

            if value in _rfc3986_unreserved:
                result.write(int2byte(value))
            else:
                result.write(("%%%02X" % value).encode("ascii"))

            i += 3
        elif c == _ascii_plus:
            # Plus-encoded space.  Convert this to %20.
            result.write(b"%20")
            i += 1
        else:
            result.write(("%%%02X" % c).encode("ascii"))
            i += 1

    result = result.getvalue()
    if not isinstance(result, string_types):
        result = str(result, "utf-8")
    return result

def get_canonical_uri_path(uri_path):
    """
    get_canonical_uri_path(uri_path) -> str

    Normalizes the specified URI path component, removing redundant slashes
    and relative path components.

    A ValueError exception is raised if:
    * The URI path is not empty and not absolute (does not start with '/').
    * A parent relative path element ('..') attempts to go beyond the top.
    * An invalid percent-encoding is encountered.
    """
    # Special case: empty path is converted to '/'
    if uri_path == "" or uri_path == "/":
        return "/"

    # All other paths must be absolute.
    if not uri_path.startswith("/"):
        raise ValueError("URI path is not absolute.")

    # Replace double slashes; this makes it easier to handle slashes at the
    # end.
    uri_path = _multislash.sub("/", uri_path)

    # Examine each path component for relative directories.
    components = uri_path.split("/")[1:]
    i = 0
    while i < len(components):
        # Fix % encodings.
        component = normalize_uri_path_component(components[i])
        components[i] = component

        if components[i] == ".":
            # Relative current directory.  Remove this.
            del components[i]

            # Don't increment i; with the deletion, we're now pointing to
            # the next element in the path.
        elif components[i] == "..":
            # Relative path: parent directory.  Remove this and the previous
            # component.
            if i == 0:
                # Not allowed at the beginning!
                raise ValueError("URI path attempts to go beyond root")
            del components[i-1:i+1]

            # Since we've deleted two components, we need to back up one to
            # examine what's now the next component.
            i -= 1
        else:
            # Leave it alone; proceed to the next component.
            i += 1

    return "/" + "/".join(components)

def normalize_query_parameters(query_string):
    """
    normalize_query_parameters(query_string) -> dict

    Converts a query string into a dictionary mapping parameter names to a
    list of the sorted values.  This ensurses that the query string follows
    % encoding rules according to RFC 3986 and checks for duplicate keys.

    A ValueError exception is raised if a percent encoding is invalid.
    """
    if query_string == "":
        return {}

    components = query_string.split("&")
    result = {}

    for component in components:
        try:
            key, value = component.split("=", 1)
        except ValueError:
            key = component
            value = ""

        if component == "":
            # Empty component; skip it.
            continue

        key = normalize_uri_path_component(key)
        value = normalize_uri_path_component(value)

        if key in result:
            result[key].append(value)
        else:
            result[key] = [value]

    return dict([(key, sorted(values))
                 for key, values in iteritems(result)])

def _get_callee_depth():
    #for depth, stack_segment in enumerate(reversed(extract_stack())):
    #    log.warning("DEPTH=%2d SS=%s", depth, stack_segment)    

    for depth, stack_segment in enumerate(reversed(extract_stack())):
        filename = stack_segment.filename
        if not filename:
            return depth

        path_parts = path_split(filename)[-2:]
        if (len(path_parts) != 2
            or basename(path_parts[0]) != "awssig"
            or splitext(path_parts[1])[0] != "sigv4"):
            return depth


# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
