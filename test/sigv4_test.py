#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from datetime import datetime, timedelta
from functools import partial
from hashlib import sha256
import hmac
import awssig.sigv4 as sigv4
from os import walk
from os.path import basename, dirname, splitext
from re import sub
from six import binary_type, iteritems, string_types
from six.moves import cStringIO, range
from string import ascii_letters, digits
from sys import stderr
from unittest import skip, TestCase

region = "us-east-1"
service = "service"
access_key = "AKIDEXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
key_mapping = { access_key: secret_key }
remove_auth = "remove_auth"
wrong_authtype = "wrong_authtype"
clobber_sig_equals = "clobber_sig_equals"
delete_credential = "delete_credential"
delete_signature = "delete_signature"
dup_signature = "dup_signature"
delete_date = "delete_date"

# Allowed characters in quoted-printable strings
allowed_qp = ascii_letters + digits + "-_.~"

class AWSSigV4TestCaseRunner(TestCase):
    basedir = dirname(__file__) + "/aws-sig-v4-test-suite/"
    tweaks = (
        "", remove_auth, wrong_authtype, clobber_sig_equals, delete_credential,
        delete_signature, dup_signature, delete_date,
    )

    def run_sigv4_case(self, filebase, tweak=""):
        filebase = self.basedir + filebase

        with open(filebase + ".sreq", "rb") as fd:
            method_line = fd.readline().strip()
            if isinstance(method_line, binary_type):
                method_line = method_line.decode("utf-8")
            headers = {}

            last_header = None

            while True:
                line = fd.readline()
                if line in (b"\n", b"",):
                    break

                line = line.decode("utf-8")
                if line.startswith(" ") or line.startswith("\t"):
                    assert last_header is not None
                    header = last_header
                    value = line.strip()
                else:
                    try:
                        header, value = line.split(":", 1)
                    except ValueError as e:
                        raise ValueError("Invalid header line: %s" % line)
                    key = header.lower()
                    value = value.strip()
                    last_header = header

                if key == "authorization":
                    if tweak == remove_auth:
                        continue
                    elif tweak == wrong_authtype:
                        value = "XX" + value
                    elif tweak == clobber_sig_equals:
                        value = value.replace("Signature=", "Signature")
                    elif tweak == delete_credential:
                        value = value.replace("Credential=", "Foo=")
                    elif tweak == delete_signature:
                        value = value.replace("Signature=", "Foo=")
                    elif tweak == dup_signature:
                        value += ", Signature=foo"
                elif key in ("date", "x-amz-date",):
                    if tweak == delete_date:
                        continue
                
                if key in headers:
                    headers[key].append(value)
                else:
                    headers[key] = [value]

            body = fd.read()

            first_space = method_line.find(" ")
            last_space = method_line.rfind(" ")
            
            method = method_line[:first_space]
            uri_path = method_line[first_space + 1:last_space]

            qpos = uri_path.find("?")
            if qpos == -1:
                query_string = ""
            else:
                query_string = uri_path[qpos+1:]
                uri_path = uri_path[:qpos]

        with open(filebase + ".creq", "r") as fd:
            canonical_request = fd.read().replace("\r", "")

        with open(filebase + ".sts", "r") as fd:
            string_to_sign = fd.read().replace("\r", "")

        v = sigv4.AWSSigV4Verifier(
            request_method=method, uri_path=uri_path, query_string=query_string,
            headers=headers, body=body, region=region, service=service,
            key_mapping=key_mapping, timestamp_mismatch=None)

        if tweak:
            try:
                v.verify()
                self.fail("Expected verify() to throw an InvalidSignature "
                          "error for tweak %s" % tweak)
            except sigv4.InvalidSignatureError:
                pass
        else:
            self.assertEqual(
                v.canonical_request, canonical_request,
                "Canonical request mismatch in %s\nExpected: %r\nReceived: %r" %
                (filebase, canonical_request, v.canonical_request))
            self.assertEqual(
                v.string_to_sign, string_to_sign,
                "String to sign mismatch in %s\nExpected: %r\nReceived: %r" %
                (filebase, string_to_sign, v.string_to_sign))
            v.verify()

    def test_get_vanilla_utf8_query(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-utf8-query/get-vanilla-utf8-query", tweak)

    def test_get_vanilla_query_order_key_case(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-query-order-key-case/get-vanilla-query-order-key-case", tweak)

    def test_get_header_value_trim(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-header-value-trim/get-header-value-trim", tweak)

    def test_get_vanilla_query_unreserved(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-query-unreserved/get-vanilla-query-unreserved", tweak)

    def test_get_vanilla_query_order_key(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-query-order-key/get-vanilla-query-order-key", tweak)

    def test_get_vanilla(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla/get-vanilla", tweak)

    def test_post_sts_token_post_sts_header_after(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-sts-token/post-sts-header-after/post-sts-header-after", tweak)

    def test_post_sts_token_post_sts_header_before(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-sts-token/post-sts-header-before/post-sts-header-before", tweak)

    def test_get_unreserved(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-unreserved/get-unreserved", tweak)

    def test_get_header_value_multiline(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-header-value-multiline/get-header-value-multiline", tweak)

    def test_post_x_www_form_urlencoded_parameters(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters", tweak)

    def test_post_vanilla(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-vanilla/post-vanilla", tweak)

    @skip("Testcase from AWS appears to be broken")
    def test_post_x_www_form_urlencoded(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-x-www-form-urlencoded/post-x-www-form-urlencoded", tweak)

    def test_post_header_key_case(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-header-key-case/post-header-key-case", tweak)

    def test_get_vanilla_empty_query_key(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-empty-query-key/get-vanilla-empty-query-key", tweak)

    def test_post_header_key_sort(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-header-key-sort/post-header-key-sort", tweak)

    def test_post_vanilla_empty_query_value(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-vanilla-empty-query-value/post-vanilla-empty-query-value", tweak)

    def test_get_utf8(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-utf8/get-utf8", tweak)

    def test_get_vanilla_query(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-query/get-vanilla-query", tweak)

    def test_get_header_value_order(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-header-value-order/get-header-value-order", tweak)

    def test_post_vanilla_query(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-vanilla-query/post-vanilla-query", tweak)

    def test_get_vanilla_query_order_value(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-vanilla-query-order-value/get-vanilla-query-order-value", tweak)

    def test_post_header_value_case(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("post-header-value-case/post-header-value-case", tweak)

    def test_normalize_path_get_slash(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-slash/get-slash", tweak)

    def test_normalize_path_get_slashes(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-slashes/get-slashes", tweak)

    def test_normalize_path_get_space(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-space/get-space", tweak)

    def test_normalize_path_get_relative(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-relative/get-relative", tweak)

    def test_normalize_path_get_slash_pointless_dot(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-slash-pointless-dot/get-slash-pointless-dot", tweak)

    def test_normalize_path_get_slash_dot_slash(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-slash-dot-slash/get-slash-dot-slash", tweak)

    def test_normalize_path_get_relative_relative(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("normalize-path/get-relative-relative/get-relative-relative", tweak)

    def test_get_header_key_duplicate(self):
        for tweak in self.tweaks:
            self.run_sigv4_case("get-header-key-duplicate/get-header-key-duplicate", tweak)


class QuerySignatures(TestCase):
    def __init__(self, *args, **kw):
        TestCase.__init__(self, *args, **kw)
        self.maxDiff = 1024

    def runTest(self):
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ten_minutes_ago = (
            datetime.utcnow() - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        today = datetime.utcnow().strftime("%Y%m%d")
        two_days_ago = (datetime.utcnow() - timedelta(days=2)).strftime("%Y%m%d")

        tests = [
            {
                'method': "GET",
                'url': "/?foo=bar",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
            },
            {
                'method': "GET",
                'url': "/?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                }
            },
            {
                'method': "POST",
                'url': "/",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
                'quote_chars': True
            },
            {
                'method': "GET",
                'url': "/?foo=bar",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
                'timestamp_mismatch': 120,
            },
            {
                'method': "GET",
                'url': "/question%3Fmark%3Furl",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
                'timestamp_mismatch': 120,
                'quote_chars': False
            },
            {
                'method': "GET",
                'url': "/?foo=bar%20ok",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
                'timestamp_mismatch': 120,
                'fix_qp': False
            }
        ]

        bad = [
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                # Decanonicalized signed-headers
                'signed_headers': ["host", "content-type"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                }
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
                # Invalid credential scope format
                'scope': "foo"
            },
            {
                'method': "POST",
                # Bad path encoding
                'url': "/%zz",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
            },
            {
                'method': "POST",
                # Relative path
                'url': "../foo",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
            },
            {
                'method': "POST",
                # Go up too far.
                'url': "/a/b/../../..",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
                # Incorrect region
                'scope': (access_key + "/" + today + "/x-foo-bar/" + service +
                          "/aws4_request")
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
                # Incorrect date
                'scope': (access_key + "/" + two_days_ago + "/" + region + "/" + service +
                          "/aws4_request")
            },
            {
                'method': "POST",
                'url': "////",
                # Invalid percent encoding
                'body': b"foo=%zz",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/octet-stream"],
                },
                'fix_qp': False
            },
            {
                'method': "GET",
                'url': "/?foo=bar",
                'body': b"",
                # Old
                'timestamp': ten_minutes_ago,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
                'timestamp_mismatch': 120,
            },
            {
                'method': "GET",
                'url': "/?foo=bar",
                'body': b"",
                # Bad format
                'timestamp': "20151008T999999Z",
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                },
            },
        ]
            
        for test in tests:
            self.verify(**test)

        for test in bad:
            with self.assertRaises(sigv4.InvalidSignatureError):
                self.verify(bad=True, **test)

        return
    
    def verify(self, method, url, body, timestamp, headers, signed_headers,
               timestamp_mismatch=60, bad=False, scope=None,
               quote_chars=False, fix_qp=True):
        date = timestamp[:8]
        credential_scope = "/".join([date, region, service, "aws4_request"])

        if scope is None:
            scope = access_key + "/" + credential_scope
        if "?" in url:
            uri, query_string = url.split("?", 1)
        else:
            uri = url
            query_string = ""

        if not fix_qp:
            scope = scope.replace("/", "%2F")

        normalized_uri = sub("//+", "/", uri)

        query_params = [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Credential=" + scope,
            "X-Amz-Date=" + timestamp,
            "X-Amz-SignedHeaders=" + ";".join(signed_headers)]
        
        if query_string:
            query_params.extend(query_string.split("&"))

        def fixup_qp(qp):
            result = cStringIO()
            key, value = qp.split("=", 1)
            for c in value:
                if c in allowed_qp:
                    result.write(c)
                else:
                    result.write("%%%02X" % ord(c))

            return key + "=" + result.getvalue()

        if fix_qp:
            canonical_query_string = "&".join(
                sorted(map(fixup_qp, [qp for qp in query_params if qp])))
        else:
            canonical_query_string = "&".join(sorted(query_params))

        canonical_headers = "".join([
            (header + ":" + ",".join(headers[header]) + "\n")
            for header in sorted(signed_headers)])

        canonical_req = (
            method + "\n" +
            normalized_uri + "\n" +
            canonical_query_string + "\n" +
            canonical_headers + "\n" +
            ";".join(signed_headers) + "\n" +
            sha256(body).hexdigest())

        string_to_sign = (
            "AWS4-HMAC-SHA256\n" +
            timestamp + "\n" +
            credential_scope + "\n" +
            sha256(canonical_req.encode("utf-8")).hexdigest())

        def sign(secret, value):
            return hmac.new(secret, value.encode("utf-8"), sha256).digest()

        k_date = sign(b"AWS4" + secret_key.encode("utf-8"), date)
        k_region = sign(k_date, region)
        k_service = sign(k_region, service)
        k_signing = sign(k_service, "aws4_request")
        signature = hmac.new(
            k_signing, string_to_sign.encode("utf-8"), sha256).hexdigest()

        query_params.append("X-Amz-Signature=" + signature)

        if quote_chars:
            bad_qp = []
            
            for qp in query_params:
                result = cStringIO()
                
                for c in qp:
                    if c.isalpha():
                        result.write("%%%02X" % ord(c))
                    else:
                        result.write(c)

                bad_qp.append(result.getvalue())
            query_params = bad_qp

        v = sigv4.AWSSigV4Verifier(
            request_method=method, uri_path=uri,
            query_string="&".join(query_params), headers=headers, body=body,
            region=region, service=service, key_mapping=key_mapping,
            timestamp_mismatch=timestamp_mismatch)
        
        if not bad:
            self.assertEqual(v.canonical_request, canonical_req)
            self.assertEqual(v.string_to_sign, string_to_sign)
        v.verify()
        return


class QueryS3Signatures(TestCase):
    def test_good_cases(self):
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ten_minutes_ago = (
            datetime.utcnow() - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        today = datetime.utcnow().strftime("%Y%m%d")
        two_days_ago = (datetime.utcnow() - timedelta(days=2)).strftime("%Y%m%d")

        tests = [
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': [sha256(b"").hexdigest()],
                },
            },
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': ["UNSIGNED-PAYLOAD"],
                },
            },
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': ["STREAMING-AWS4-HMAC-SHA256-PAYLOAD"],
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': [sha256(b"").hexdigest()],
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/x-www-form-urlencoded; charset=UTF-8"],
                    'x-amz-content-sha256': [sha256(b"foo=bar").hexdigest()],
                }
            },
            {
                'method': "POST",
                'url': "/",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': ["host.example.com"],
                    'content-type': ["application/x-www-form-urlencoded; charset=UTF-8"],
                    'x-amz-content-sha256': [sha256(b"foo=bar").hexdigest()],
                },
                'quote_chars': True
            },
            {
                'method': "GET",
                'url': "/?foo=bar",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.amazonaws.com"],
                    'x-amz-content-sha256': [sha256(b"").hexdigest()],
                },
                'timestamp_mismatch': 120,
            },
        ]

        for test in tests:
            self.verify(**test)

        return

    def test_missing_content_sha256_header(self):
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ten_minutes_ago = (
            datetime.utcnow() - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        today = datetime.utcnow().strftime("%Y%m%d")
        two_days_ago = (datetime.utcnow() - timedelta(days=2)).strftime("%Y%m%d")

        tests = [
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                },
            },
        ]

        for test in tests:
            with self.assertRaises(sigv4.InvalidSignatureError):
                self.verify(bad=True, **test)

    def test_bad_content_sha256_header(self):
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ten_minutes_ago = (
            datetime.utcnow() - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        today = datetime.utcnow().strftime("%Y%m%d")
        two_days_ago = (datetime.utcnow() - timedelta(days=2)).strftime("%Y%m%d")

        tests = [
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': ["hello world"],
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': ["host.us-east-1.s3.amazonaws.com"],
                    'x-amz-content-sha256': ["abcd1234"],
                },
            },
        ]

        for test in tests:
            with self.assertRaises(sigv4.InvalidSignatureError):
                self.verify(bad=True, **test)

    def verify(self, method, url, body, timestamp, headers, signed_headers,
               timestamp_mismatch=60, bad=False, scope=None,
               quote_chars=False, fix_qp=True):
        date = timestamp[:8]
        credential_scope = "/".join([date, region, service, "aws4_request"])

        if scope is None:
            scope = access_key + "/" + credential_scope
        if "?" in url:
            uri, query_string = url.split("?", 1)
        else:
            uri = url
            query_string = ""

        query_params = [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Credential=" + scope,
            "X-Amz-Date=" + timestamp,
            "X-Amz-SignedHeaders=" + ";".join(signed_headers)]
        
        if query_string:
            query_params.extend(query_string.split("&"))

        def fixup_qp(qp):
            result = cStringIO()
            key, value = qp.split("=", 1)
            for c in value:
                if c in allowed_qp:
                    result.write(c)
                else:
                    result.write("%%%02X" % ord(c))

            return key + "=" + result.getvalue()

        if fix_qp:
            canonical_query_string = "&".join(
                sorted(map(fixup_qp, [qp for qp in query_params if qp])))
        else:
            canonical_query_string = "&".join(sorted(query_params))

        canonical_headers = "".join([
            (header + ":" + ",".join(headers[header]) + "\n")
            for header in sorted(signed_headers)])

        canonical_req = (
            method + "\n" +
            uri + "\n" +
            canonical_query_string + "\n" +
            canonical_headers + "\n" +
            ";".join(signed_headers) + "\n" +
            headers.get("x-amz-content-sha256", [sha256(body).hexdigest()])[0])

        string_to_sign = (
            "AWS4-HMAC-SHA256\n" +
            timestamp + "\n" +
            credential_scope + "\n" +
            sha256(canonical_req.encode("utf-8")).hexdigest())

        def sign(secret, value):
            return hmac.new(secret, value.encode("utf-8"), sha256).digest()

        k_date = sign(b"AWS4" + secret_key.encode("utf-8"), date)
        k_region = sign(k_date, region)
        k_service = sign(k_region, service)
        k_signing = sign(k_service, "aws4_request")
        signature = hmac.new(
            k_signing, string_to_sign.encode("utf-8"), sha256).hexdigest()

        query_params.append("X-Amz-Signature=" + signature)

        if quote_chars:
            bad_qp = []
            
            for qp in query_params:
                result = cStringIO()
                
                for c in qp:
                    if c.isalpha():
                        result.write("%%%02X" % ord(c))
                    else:
                        result.write(c)

                bad_qp.append(result.getvalue())
            query_params = bad_qp

        v = sigv4.AWSSigV4S3Verifier(
            request_method=method, uri_path=uri,
            query_string="&".join(query_params), headers=headers, body=body,
            region=region, service=service, key_mapping=key_mapping,
            timestamp_mismatch=timestamp_mismatch)
        
        if not bad:
            self.assertEqual(v.canonical_request, canonical_req)
            self.assertEqual(v.string_to_sign, string_to_sign)
        v.verify()
        return

class BadInitializer(TestCase):
    def test_request_method(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(request_method=None)

    def test_uri_path(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(uri_path=None)
    
    def test_query_string(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(query_string=None)

    def test_headers(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(headers=None)

        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(headers={"Host": 0})

        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(headers={0: "Foo"})

    def test_body(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(body=None)

        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(body=u"Hello")

    def test_region(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(region=None)

    def test_service(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(service=None)

    def test_timestamp_mismatch(self):
        with self.assertRaises(TypeError):
            sigv4.AWSSigV4Verifier(timestamp_mismatch="Hello")

        with self.assertRaises(ValueError):
            sigv4.AWSSigV4Verifier(timestamp_mismatch=-1)
