#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from datetime import datetime, timedelta
from functools import partial
from glob import glob
from hashlib import sha256
import hmac
import awssig.sigv4 as sigv4
from os.path import basename, dirname, splitext
from re import sub
from six import binary_type, iteritems, string_types
from six.moves import cStringIO, range
from string import ascii_letters, digits
from unittest import TestCase

region = "us-east-1"
service = "host"
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

ONE_THOUSAND_YEARS = 1000 * 365 * 24 * 60 * 60

class AWSSigV4TestCaseRunner(TestCase):
    def __init__(self, filebase, tweaks="", methodName="runTest"):
        super(AWSSigV4TestCaseRunner, self).__init__(methodName=methodName)
        #if filebase == "runTest":
        #    raise ValueError()
        self.filebase = filebase
        self.tweaks = tweaks
        return
        
    def runTest(self):
        with open(self.filebase + ".sreq", "rb") as fd:
            method_line = fd.readline().strip()
            if isinstance(method_line, binary_type):
                method_line = method_line.decode("utf-8")
            headers = {}

            while True:
                line = fd.readline()
                if line in (b"\r\n", b""):
                    break

                self.assertTrue(line.endswith(b"\r\n"))
                line = line.decode("utf-8")
                header, value = line[:-2].split(":", 1)
                key = header.lower()
                value = value.strip()

                if key == "authorization":
                    if self.tweaks == remove_auth:
                        continue
                    elif self.tweaks == wrong_authtype:
                        value = "XX" + value
                    elif self.tweaks == clobber_sig_equals:
                        value = value.replace("Signature=", "Signature")
                    elif self.tweaks == delete_credential:
                        value = value.replace("Credential=", "Foo=")
                    elif self.tweaks == delete_signature:
                        value = value.replace("Signature=", "Foo=")
                    elif self.tweaks == dup_signature:
                        value += ", Signature=foo"
                elif key == "date":
                    if self.tweaks == delete_date:
                        continue
                
                if key in headers:
                    headers[key].append(value)
                else:
                    headers[key] = [value]

            headers = dict([(key, ",".join(sorted(values)))
                            for key, values in iteritems(headers)])
            body = fd.read()

            first_space = method_line.find(" ")
            second_space = method_line.find(" ", first_space + 1)
            
            method = method_line[:first_space]
            uri_path = method_line[first_space + 1:second_space]

            qpos = uri_path.find("?")
            if qpos == -1:
                query_string = ""
            else:
                query_string = uri_path[qpos+1:]
                uri_path = uri_path[:qpos]

        with open(self.filebase + ".creq", "r") as fd:
            canonical_request = fd.read().replace("\r", "")

        with open(self.filebase + ".sts", "r") as fd:
            string_to_sign = fd.read().replace("\r", "")

        v = sigv4.AWSSigV4Verifier(
            request_method=method, uri_path=uri_path, query_string=query_string,
            headers=headers, body=body, region=region, service=service,
            key_mapping=key_mapping, timestamp_mismatch=ONE_THOUSAND_YEARS)

        if self.tweaks:
            try:
                v.verify()
                self.fail("Expected verify() to throw an InvalidSignature "
                          "error")
            except sigv4.InvalidSignatureError:
                pass
        else:
            self.assertEqual(
                v.canonical_request, canonical_request,
                "Canonical request mismatch in %s\nExpected: %r\nReceived: %r" %
                (self.filebase, canonical_request, v.canonical_request))
            self.assertEqual(
                v.string_to_sign, string_to_sign,
                "String to sign mismatch in %s\nExpected: %r\nReceived: %r" %
                (self.filebase, string_to_sign, v.string_to_sign))
            v.verify()

        return
    # end runTest

    def __str__(self):
        return "AWSSigV4TestCaseRunner: %s" % basename(self.filebase)
# end AWSSigV4TestCaseRunner

class QuerySignatures(TestCase):
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
                    'host': "host.us-east-1.amazonaws.com",
                },
            },
            {
                'method': "GET",
                'url': "/?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.amazonaws.com",
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                }
            },
            {
                'method': "POST",
                'url': "/",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.us-east-1.amazonaws.com",
                },
                'timestamp_mismatch': 120,
            },
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                }
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
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
                    'host': "host.us-east-1.amazonaws.com",
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
                    'host': "host.us-east-1.amazonaws.com",
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
            (header + ":" + headers[header] + "\n")
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
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': sha256(b"").hexdigest(),
                },
            },
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': "UNSIGNED-PAYLOAD",
                },
            },
            {
                'method': "GET",
                'url': "/a/b",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': sha256(b"").hexdigest(),
                },
            },
            {
                'method': "POST",
                'url': "////",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                    'x-amz-content-sha256': sha256(b"foo=bar").hexdigest(),
                }
            },
            {
                'method': "POST",
                'url': "/",
                'body': b"foo=bar",
                'timestamp': now,
                'signed_headers': ["content-type", "host"],
                'headers': {
                    'host': "host.example.com",
                    'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                    'x-amz-content-sha256': sha256(b"foo=bar").hexdigest(),
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
                    'host': "host.us-east-1.amazonaws.com",
                    'x-amz-content-sha256': sha256(b"").hexdigest(),
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
                    'host': "host.us-east-1.s3.amazonaws.com",
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.s3.amazonaws.com",
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
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': "hello world",
                },
            },
            {
                'method': "GET",
                'url': "/a/b?foo=bar&&baz=yay",
                'body': b"",
                'timestamp': now,
                'signed_headers': ["host"],
                'headers': {
                    'host': "host.us-east-1.s3.amazonaws.com",
                    'x-amz-content-sha256': "abcd1234",
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
            (header + ":" + headers[header] + "\n")
            for header in sorted(signed_headers)])

        canonical_req = (
            method + "\n" +
            uri + "\n" +
            canonical_query_string + "\n" +
            canonical_headers + "\n" +
            ";".join(signed_headers) + "\n" +
            headers.get("x-amz-content-sha256", sha256(body).hexdigest()))

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

# Hide the test case class from automatic module discovery tools.
_test_classes = [AWSSigV4TestCaseRunner]
del AWSSigV4TestCaseRunner

def test_aws_suite():
    global AWSSigV4TestCaseRunner
    AWSSigV4TestCaseRunner = _test_classes[0]
    tests = []
    for filename in glob(dirname(__file__) + "/aws4_testsuite/*.req"):
        filebase = splitext(filename)[0]
        tests.append(AWSSigV4TestCaseRunner(filebase))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=remove_auth))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=wrong_authtype))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=clobber_sig_equals))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=delete_credential))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=delete_signature))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=dup_signature))
        tests.append(AWSSigV4TestCaseRunner(filebase, tweaks=delete_date))

    for i, test in enumerate(tests):
        test.runTest()

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
