package nl.trusttech.service;

import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;
import org.multipaz.asn1.*;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.Tstr;

import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


import static org.junit.jupiter.api.Assertions.*;

public class AttestationTest {
    public static String iosAttestation = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZBBMwggQPMIIDlaADAgECAgYBoaq8MvYwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjYxMTA0MDgwMzQyWhcNMjYxMTA3MDgwMzQyWjCBkTFJMEcGA1UEAwxAZmRjM2IyZjY1NDk0MzEyZDY0MGI5YjAxODFiMzg4ZjEyZTk1M2M3YjNiODE2OGZlOTg5OWM2YWUyZDE4NWVkNTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThWwdN377fLMOF3fVK2l6l5T1Z3Xy/1uCYGAu2AaaENvnQmX2wUPVY1SOnATQGY1vRv1biSby2KQnd8PB7qClSo4ICGDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwFAYDVR0lBA0wCwYJKoZIhvdjZAQYMHkGCSqGSIb3Y2QIBQRsMGqkAwIBCr+JMAMCAQC/iTEDAgEAv4kyAwIBAL+JMwMCAQC/iTQdBBs2NFNYNEw4U1g3LmNvbS5tZXJjay53YWxsZXS/iTYDAgEEv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBAKoDAgEAMIHTBgkqhkiG92NkCAcEgcUwgcK/ingIBAYyNi42LjK/iFADAgECv4p5CQQHMS4wLjI0OL+KewcEBTIzRzkwv4p8CAQGMjYuNi4yv4p9CAQGMjYuNi4yv4p+AwIBAL+KfwMCAQC/iwADAgEAv4sBAwIBAL+LAgMCAQC/iwMDAgEAv4sEAwIBAb+LBQMCAQC/iwoPBA0yMy43LjkwLjAuMCwwv4sLDwQNMjMuNy45MC4wLjAsML+LDA8EDTIzLjcuOTAuMC4wLDC/iAIKBAhpcGhvbmVvczAzBgkqhkiG92NkCAIEJjAkoSIEIJfMdWJcdp6yx1Cso8mhYCMUcplc1lFDq+1sdv8zMMwKMFgGCSqGSIb3Y2QIBgRLMEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/MAoGCCqGSM49BAMCA2gAMGUCMCn+mjcdI/LPHvwPvX+KkaGKjv2qDTJaVHKW8e2pKl9cp3xVOYmvqvtMLvxNXNjzmQIxALM86ZbaGIQyOTnk1n7Uv/55K1E28g1tLoWaEPyNdqJAQCEpBpq9JMHJnro/J+C2YVkCRzCCAkMwggHIoAMCAQICEAm6xeG8QBrZ1FOVvDgaCFQwCgYIKoZIzj0EAwMwUjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzOTU1WhcNMzAwMzEzMDAwMDAwWjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK5bN6B3TXmyNY9A59HyJibxwl/vF4At6rOCalmHT/jSrRUleJqiZgQZEki2PLlnBp6Y02O9XjcPv6COMp6Ac6mF53Ruo1mi9m8p2zKvRV4hFljVZ6+eJn6yYU3CGmbOmaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSskRBTM72+aEH/pwyp5frq5eWKoTAdBgNVHQ4EFgQUPuNdHAQZqcm0MfiEdNbh4Vdy45swDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2kAMGYCMQC7voiNc40FAs+8/WZtCVdQNbzWhyw/hDBJJint0fkU6HmZHJrota7406hUM/e2DQYCMQCrOO3QzIHtAKRSw7pE+ZNjZVP+zCl/LrTfn16+WkrKtplcS4IN+QQ4b3gHu1iUObdncmVjZWlwdFkPeDCABgkqhkiG9w0BBwKggDCAAgEBMQ8wDQYJYIZIAWUDBAIBBQAwgAYJKoZIhvcNAQcBoIAkgASCA+gxggUvMCMCAQICAQEEGzY0U1g0TDhTWDcuY29tLm1lcmNrLndhbGxldDCCBB0CAQMCAQEEggQTMIIEDzCCA5WgAwIBAgIGAaGqvDL2MAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MTEwNDA4MDM0MloXDTI2MTEwNzA4MDM0MlowgZExSTBHBgNVBAMMQGZkYzNiMmY2NTQ5NDMxMmQ2NDBiOWIwMTgxYjM4OGYxMmU5NTNjN2IzYjgxNjhmZTk4OTljNmFlMmQxODVlZDUxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4VsHTd++3yzDhd31StpepeU9Wd18v9bgmBgLtgGmhDb50Jl9sFD1WNUjpwE0BmNb0b9W4km8tikJ3fDwe6gpUqOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDB5BgkqhkiG92NkCAUEbDBqpAMCAQq/iTADAgEAv4kxAwIBAL+JMgMCAQC/iTMDAgEAv4k0HQQbNjRTWDRMOFNYNy5jb20ubWVyY2sud2FsbGV0v4k2AwIBBL+JNwMCAQC/iTkDAgEAv4k6AwIBAL+JOwMCAQCqAwIBADCB0wYJKoZIhvdjZAgHBIHFMIHCv4p4CAQGMjYuNi4yv4hQAwIBAr+KeQkEBzEuMC4yNDi/insHBAUyM0c5ML+KfAgEBjI2LjYuMr+KfQgEBjI2LjYuMr+KfgMCAQC/in8DAgEAv4sAAwIBAL+LAQMCAQC/iwIDAgEAv4sDAwIBAL+LBAMCAQG/iwUDAgEAv4sKDwQNMjMuNy45MC4wLjAsML+LCw8EDTIzLjcuOTAuMC4wLDC/iwwPBA0yMy43LjkwLjAuMCwwv4gCCgQIaXBob25lb3MwMwYJKoZIhvdjZAgCBCYwJKEiBCCXzHViXHaessdQrKPJoWAjFHKZXNZRQ6vtbHb/MzDMCjBYBgkqhkiG92NkCAYESzBJo0cERTBDDAIxMTA9MAoMA29rZKEDAQH/MAkMAm9hoQMBAf8wCwwEb3NnbqEDAQH/MAsMBG9kZWyhAwEB/zAKDANvY2uhAwEB/zAKBggqhkjOPQQDAgNoADBlAjApBIIBS/6aNx0j8s8e/A+9f4qRoYqO/aoNMlpUcpbx7akqX1ynfFU5ia+q+0wu/E1c2POZAjEAszzpltoYhDI5OeTWftS//nkrUTbyDW0uhZoQ/I12okBAISkGmr0kwcmeuj8n4LZhMCgCAQQCAQEEIBohoukQCFwdl1MdLTz64RsgT7EYLnyWkBvi6xRgteLaMGACAQUCAQEEWE5wYjlvTHZOeEphZlduWlRWVER5aTdUc05NZEZIWUxudWU3VnZmQzRVQUl5dUFvb0RuZkFQbU5hNGc4RVVaMWtNeFlQOHM4QnZ6N2IzcE0vSkthU1l3PT0wDgIBBgIBAQQGQVRURVNUMA8CAQcCAQEEB3NhbmRib3gwHAIBDAIBAQQUMjAyNi0xMS0wNVQwODowMzo0M1owHAIBFQIBAQQUMjAyNy0wMi0wM1QwODowMzo0M1oAAAAAAACggDCCA64wggNUoAMCAQICEGYCOIAAFCb3XYsOFSxfbkMwCgYIKoZIzj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjYwMTIwMjAyMTA5WhcNMjcwMjE4MTg1ODM5WjBaMTYwNAYDVQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOxiuzsUZrYpTUbRARLSjA5lXtM29W4Uf4Bpv7eKN77D6sMNqAqQfRG4AbVgOVopngIkH80iAkUOLIM6qTJ3cVqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFDRViXB0YA4i0rpnz6VbacIj8cooMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0gAMEUCIBxnl7mCRdHW3HIEt5sCPK/4e/Lv+JN91yDEXorkZcLrAiEA/MhZhM7JoSzChqnUknb98NL2Jdx1/Hz4h0Vpe+YeqrQwggL5MIICf6ADAgECAhBW+4PUK/+NwzeZI7Varm69MAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE5MDMyMjE3NTMzM1oXDTM0MDMyMjAwMDAwMFowfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSzmO9fYaxqygKOxzhr/sElICRrPYx36bLKDVvREvhIeVX3RKNjbqCfJW+Sfq+M8quzQQZ8S9DJfr0vrPLg366o4H3MIH0MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFNkX/ktnkDhLkvTbztVXgBQLjz3JMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIDBAIFADAKBggqhkjOPQQDAwNoADBlAjEAjW+mn6Hg5OxbTnOKkn89eFOYj/TaH1gew3VK/jioTCqDGhqqDaZkbeG5k+jRVUztAjBnOyy04eg3B3fL1ex2qBo6VTs/NWrIxeaSsOFhvoBJaeRfK6ls4RECqsxh2Ti3c0owggJDMIIByaADAgECAggtxfyI0sVLlTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xNDA0MzAxODE5MDZaFw0zOTA0MzAxODE5MDZaMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmOkvPUBypO2TInKBExzdEJXxxaNOcdwUFtkO5aYFKndke19OONO7HES1f/UftjJiXcnphFtPME8RWgD9WFgMpfUPLE0HRxN12peXl28xXO0rnXsgO9i5VNlemaQ6UQoxo0IwQDAdBgNVHQ4EFgQUu7DeoVgziJqkipnevr3rr9rLJKswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWXhpdNBjZ7e/0bA4ARku437JGEcUP/eZ6jKGma87CA9Sc9ZPGdLhq36ojFQIwbWaKEMrUDdRPzY1DPrSKY6UzbuNt2he3ZB/IUyb5iGJ0OQsXW8tRqAzoGAPnorIoAAAxgf4wgfsCAQEwgZAwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEGYCOIAAFCb3XYsOFSxfbkMwDQYJYIZIAWUDBAIBBQAwCgYIKoZIzj0EAwIESDBGAiEA4UsZ0Aslh+XmFld7yfp3CKXVg0rmRAkusXyLPAbWwKcCIQC0+XEPQxdiUcNQUO8G19DxcchO3P9JxRlzawlA9lO+jgAAAAAAAGhhdXRoRGF0YVikCt8mwCgeOt/aV8zNF4XaAjomtPYSzm3yjZo4R9cLtadAAAAAAGFwcGF0dGVzdGRldmVsb3AAIP3DsvZUlDEtZAubAYGziPEulTx7O4Fo/piZxq4tGF7VpQECAyYgASFYIOFbB03fvt8sw4Xd9UraXqXlPVndfL/W4JgYC7YBpoQ2Ilgg+dCZfbBQ9VjVI6cBNAZjW9G/VuJJvLYpCd3w8HuoKVI=";
    public static String androidAttestation = "WyJNSUlDbmpDQ0FrT2dBd0lCQWdJQkFUQUtCZ2dxaGtqT1BRUURBakE1TVF3d0NnWURWUVFNREFOVVJVVXhLVEFuQmdOVkJBVVRJREJrT1RaaFpqVmhPRGhoTlRVd01UaGpaRGd3T0RreU9HWTVOREEzWWpBMk1CNFhEVEl5TURNeU1ERTVNVEl6T0ZvWERUTXlNRE14TnpFNU1USXpPRm93SHpFZE1Cc0dBMVVFQXhNVVFXNWtjbTlwWkNCTFpYbHpkRzl5WlNCTFpYa3dXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUkowVE1PN3FLL0hWUnpYR2psV2RVZjdQNE9LOEFsRUI2WXVIVnY1bTJ4VFVSWjhXeWhBQmZvWWFFb0JwNWcvWThFSWQ4V2tDSktkMlVURzhZSGoxZW1vNElCVkRDQ0FWQXdnZ0U4QmdvckJnRUVBZFo1QWdFUkJJSUJMRENDQVNnQ0FXUUtBUUVDQVdRS0FRRUVFREE1T1RZeU5EVTFOalk1T1Rrd05UZ0VBREJYdjRVOUNBSUdBYUd2cUdvY3Y0VkZSd1JGTUVNeEhUQWJCQlp1YkM1MGNuVnpkSFJsWTJndWQyRnNiR1YwWVhCd0FnRUZNU0lFSVByR0YwWGNDUU40YjdudDVpcVdLem1mYzBqd3UyK0ptNE15Wm5XUkF6dWNNSUdzb1FneEJnSUJBZ0lCQTZJREFnRURvd1FDQWdFQXBRVXhBd0lCQktvREFnRUJ2NE40QXdJQkE3K0RlUU1DQVR5L2hUNERBZ0VBdjRWQVREQktCQ0RyNkZDV1dnNEJSVDQwaVNxelJGczlQU2czMTRGSU9GckNnMUFUbmw2SVZRRUIvd29CQUFRZ1JOMGJoWEdCaDEyK0JvU0puaXBvSWpiT08wMjV0YmRhbkR0TmhWbFNSSk8vaFVFRkFnTUIrOUMvaFVJRkFnTURGajIvaFU0R0FnUUJOSy9WdjRWUEJnSUVBVFN2MVRBT0JnTlZIUThCQWY4RUJBTUNCNEF3Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQU9xbGtwbUswbXZLUFJQM3BWZjAyN2NsY3dXYUU5cGZxN1VRUU1VaWMwTHpBaUVBaU5XbllnaDQ0UXJzbW5SWFVxUjZEUTZFdzFPMURnblEyakJPbmxsOEVjMD0iLCJNSUlCOURDQ0FYcWdBd0lCQWdJUkFPZFo4UzR6RmxiVWJQUys4eDFoMFlVd0NnWUlLb1pJemowRUF3SXdPVEVNTUFvR0ExVUVEQXdEVkVWRk1Ta3dKd1lEVlFRRkV5QXpabUkyWlRZek1Ea3haR1V5Tm1JNE5UbGxaRGxpTkROa09XUTROR1ZtWkRBZUZ3MHlNakF6TWpBeE9URXlNemhhRncwek1qQXpNVGN4T1RFeU16aGFNRGt4RERBS0JnTlZCQXdNQTFSRlJURXBNQ2NHQTFVRUJSTWdNR1E1Tm1GbU5XRTRPR0UxTlRBeE9HTmtPREE0T1RJNFpqazBNRGRpTURZd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSYVdFL3Z2REFiTFJkRUl2RWpVNFBYTDFxVFRSOGZDWVIwaFkyR0FHUXJjdWgxVk5JZENrYVpZMzJRU1BYdmRKQWNHUUFQd3BNNlZscnpzMUZ0dkR4ZG8yTXdZVEFkQmdOVkhRNEVGZ1FVd3dXT3dUV0dDOStTYTU3Q2Y4T1hhRjRCM0xNd0h3WURWUjBqQkJnd0ZvQVVxUjFlTWtqU1FvMENyclBYWlJaZVlUVDlvYkl3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFPQmdOVkhROEJBZjhFQkFNQ0FnUXdDZ1lJS29aSXpqMEVBd0lEYUFBd1pRSXdRWFVKbzl4ek9KcG5SZVBXMGxBQThwVmdkTWQxc1BFVnZST3ZUOTBFd2NPN2ZZbDVnOEd2UGNJMnoyb1VrWUo4QWpFQWl1WGJ2QkJtRk82d2lVTzJ0K2FQYmNaMW8yK0VwcnkyTVI3NWEvQ0RvV1c0M0V1SGJtbEZheTE2Rlo1VGI0Z3YiLCJNSUlEa3pDQ0FYdWdBd0lCQWdJUU80UHd6ZjdDVjcxbkwrV0NzYUw3c3pBTkJna3Foa2lHOXcwQkFRc0ZBREFiTVJrd0Z3WURWUVFGRXhCbU9USXdNRGxsT0RVellqWmlNRFExTUI0WERUSXlNRE15TURFNU1USXdObG9YRFRNeU1ETXhOekU1TVRJd05sb3dPVEVNTUFvR0ExVUVEQXdEVkVWRk1Ta3dKd1lEVlFRRkV5QXpabUkyWlRZek1Ea3haR1V5Tm1JNE5UbGxaRGxpTkROa09XUTROR1ZtWkRCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaUEySUFCTlgwVkYrQ010VGFBY2owNFBLSGVhMHdxRFZRV0JqYXgveDRYU1kreWhzTzE0bXNjblQ0WEJMZFhaSXovU2NlaFZST3M5TGVKdWkxcGplNnl6YVNRVGpZenpLV1lkcVc5eURSbVNsUHJGSnNvR1QyUXpnT0RQTDE3dHp2VmlYTDBxTmpNR0V3SFFZRFZSME9CQllFRktrZFhqSkkwa0tOQXE2ejEyVVdYbUUwL2FHeU1COEdBMVVkSXdRWU1CYUFGRFpoNFFCOGlBVUpVWXRFYkVmL0dreko2azhTTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RGdZRFZSMFBBUUgvQkFRREFnSUVNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUFyNDdaUWFCY1R3RGJnbk53WS82TVhlbncrNHFJek14T1ppYkxqYWxyY0FXVW91Y25ITndrZVZBbzVvUWs0UmNxS09lQVhPYk1TZ09sWURnaDc4ZkQyekxqT2lGUlZvZXJQYVZsem0wbFk4ZlZMWkdCVlFBNlI2OWQ2MjdKcDdoUzhXM0EyNHBnZktROVFKbmx4TCtVU0xwOWJLdjk0T2U1WnhzTkJYblAvdWdLZjdIa2szYjl6RTlVbmlNU255Wm1rZG54aTQ4TnBOZFVjSmY0ZWNrR1lIdjhNVy94bEYwWHh5b0xFZCtHdjVBanFOam5jL2NrVlVadnkvOEVXY3dvTGZ6SzZNeXNlbEVnOVN5UUVvL1d1TmQ0VTJGazJWUzd3WFZ5b1Q4c0dtdEFBL1pTTDNtSDlDMDVtN1NKY0w3RHpURUkyNTZLL2x6OWUwOVJTZ1dRWkl0QlRLckk2d05nbDB6U0dkSGJZZVR6RjhPMEc4N2RRSTUrUHpXQzNsMjBCNEp0VEgrRXUwSG56c25mYmJNT2FjQ0o0MGlxR0xtRSs1UkZBeXVlWjBYeHJBcnRoODRGSFVyTmdZRk9rUmVEd1IrMW5xNW5NQkR2TkFmZXV0c3o2bUZaM1JRdm5OeCt5M05ycjJSWVFIZDMzdWpsS2hHOWVzSStpOXY2V1E3M1hXOWE3UXFvSE9JN3k1MWY3cWhQNGkreWJ4OFpxZWNKTHoxUmNPVHZsbzZWNWt0TFk5UmdZV1BGZWZSK3NrdmovUStxYzBLZ2RqR2hSK0kydWtNd01hWkE4d01XQmlXSnJEdjZnQUJyMXIvcVFndXp5Mm1ERGlTaktFQUViTTg2aTJETkMxbTdGamR1cVJqVHY2b1pYL1liZ0M0NWV5eThVZlZzVzAvUG5VZz09IiwiTUlJRkhEQ0NBd1NnQXdJQkFnSUpBUEhCY3FhWjZ2VWRNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1Cc3hHVEFYQmdOVkJBVVRFR1k1TWpBd09XVTROVE5pTm1Jd05EVXdIaGNOTWpJd016SXdNVGd3TnpRNFdoY05OREl3TXpFMU1UZ3dOelE0V2pBYk1Sa3dGd1lEVlFRRkV4Qm1PVEl3TURsbE9EVXpZalppTURRMU1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBcjdiSGdpdXhwd0hzSzdRdWk4eFVGbU9yNzVndk1zZC9kVEVEREpkU1N4dGY2QW43eHlxcFJSOTBQTDJhYnhNMWRFcWxYbmYydHF3MU5lNFh3bDVqbFJmZG5KTG1OMHBUeS80bGo0Lzd0djBTazNpaUtreXBuRVV0UjZXZk1nSDBRWmZLSE0xK2RpK3k5VEZSdHY2eS8vMHJiK1QrVzhhOW5zTkwvZ2dqbmFyODY0NjFxTzByT3MyY1hqcDNrT0cxRkVKNU1WbUZtQkd0bnJLcGE3M1hwWHlUcVJ4Qi9NMG4xbi9XOW5HcUM0RlNZYTA0VDZONVJJWkdCTjJ6Mk1UNUlLR2JGbGJDOFVyVzBEeFc3QVlJbVFRY0h0R2wvbTAwUUxWV3V0SFFvVkpZbkZQbFhUY0hZdkFTTHUrUmhoc2JEbXhNZ0pKMG1jRHB2c0M0UGp2QitUeHl3RWxnUzcwdkUwWG1MRCtPSnR2c0JzbEhadlBCS0NPZFQwTVMrdGdTT0lmZ2ErejFaMWc3K0RWYWdmN3F1dm1hZzhqZlBpb3lLdnhuSy9FZ3NUVVZpMmdoenE4d20yN3VkL21JTTdBWTJxRU9SUjhHbzNUVkI0SHpXUWdwWnJ0M2k1TUlsQ2FZNTA0THpTUmlpZ0hDekFQbEh3cytXMHJCNU4rZXI1LzJwSktuZkJTRGlDaUZBVnRDTE9aN2dMaU1tMGpoTzJCNnRVWEhJLytNUlBqeTAyaTU5bElOTVJSZXY1NkdLdGNkOXFPLzBrVUpXZFpUZEEyWG9TODJpeFB2WnRYUXBVcHVMMTJhYis5RWFESzhaNFJISllZZkNUM1E1dk5BWGFpV1ErOFBUV20yUWdCUi9ia3dTV2MrTnBVRmdOUE45UHZRaThXRWc1VW1BR01DQXdFQUFhTmpNR0V3SFFZRFZSME9CQllFRkRaaDRRQjhpQVVKVVl0RWJFZi9Ha3pKNms4U01COEdBMVVkSXdRWU1CYUFGRFpoNFFCOGlBVUpVWXRFYkVmL0dreko2azhTTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RGdZRFZSMFBBUUgvQkFRREFnSUVNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUI4Y01xVGxsSGM4VStxQ3JPbGczSDcxNzRsbWFDc2JvL2JKMEMxN0pFZ01MYjRrdnJxc1haczAxVTNtQi9xQUJnLzF0NVBkNUFPUkhBUnMxaGhxR0lDVy9uS01hdjU3NGY5clpONFBDMlpsdWZHWGI3c0lkSnBHaU85Y3RSaGlMdVl1bHkxMEpjY1VaR0VIcEhTWU0yR3RrZ1liWmJhNmxzQ1BZQUFQODNjeURWKzFhT2tUZjFSQ3AvbE0wUEt2bXhZTjEwUllzSzYzMWpybGVHZGNka3hvU0svL21TUWJnY1dubUFFWnJ6SG9GMS8wZ3NvMUhaZ0luMFlMelZoTFNBL2lYQ1g0UVQyaDNKNXozem5sdUtHMW52OE5RZHhlaTJESUloQVNXZnU4MDRDQTk2Y1FLVFRsYWFlMmZ3ZXFYamROMS92Mm5xT2huZ055ejEzNjFtRm1yNFhtYUtIL0l0VHdPZTcyTkk5WmN3UzFsVmFDdnNJa1REQ0VYZG05ckNOUEFZMTBpVHVuSUhGWFJoKzdLUHpsSEdld0NxLzhUT29oQlJuMC9OTmZoN3VSc2xPU1oveEtiTjl0TUJ0dzM3WjhkMnZ2blhxL1lXZHNtMStKTFZ3bjZ5WUQveWFjTkpCbHdwZGRsYThlYVZNanNGNm5CbklnUU9mOXpLU2UwNm5TVHF2Z3dVSG9zZ09FQ1pKWjFFdXpiSDR5c3didDAydEt0S0VGaHgrditPVGdlLzA2VitqR3NxVFdMc2ZyT0NOTHVBOEgrK3orcFVFTm1wcW5uSG92YUk0N2dDK1ROcGtnWUdra0JUNkIvbS9VMDFCdU9CQlR6aElsTUVacTlxa0RXdU0yY0E1a1c1VjNGSlVjZkhudzFJZFlJZzJXeGc3eUhjUVplbUZRZz09Il0=";

    public static Map<String, Object> deviceKeyJwk = Map.of(
            "kty", "EC",
            "crv", "P-256",
            "x", "SdEzDu6ivx1Uc1xo5VnVH-z-DivAJRAemLh1b-ZtsU0",
            "y", "RFnxbKEAF-hhoSgGnmD9jwQh3xaQIkp3ZRMbxgePV6Y"
    );

    private static final String ANDROID_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    // Security levels
    private static final int SOFTWARE = 0;
    private static final int TEE = 1;
    private static final int STRONGBOX = 2;

    // Key origin
    private static final int KM_ORIGIN_GENERATED = 0;
    private static final int ORIGIN = 702;

    @Test
    void decompileAppAttest() {
        var attestationBytes = Base64.getDecoder().decode(iosAttestation);

        var attestationCbor = Cbor.INSTANCE.decode(attestationBytes);
        var fmt = attestationCbor.getAsMap().get(new Tstr("fmt"));

        var attStmt = attestationCbor.getAsMap().get(new Tstr("attStmt")).getAsMap();
        var authData = attestationCbor.getAsMap().get(new Tstr("authData")).getAsBstr();

        var x5c = attStmt.get(new Tstr("x5c")).getAsArray();
        var leaf = x5c.get(0).getAsBstr();
        var intermediate = x5c.get(1).getAsBstr();
        var receipt = attStmt.get(new Tstr("receipt")).getAsBstr();

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var leafCert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(leaf));
            var intermdiateCert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(intermediate));

            InputStream rootStream = URI.create("https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem").toURL().openStream();
            var rootCert = (X509Certificate) factory.generateCertificate(rootStream);

            assertTrue(verifyAppleAppAttestCertChain(rootCert, intermdiateCert, leafCert));

            // --- Validity window from the leaf credential certificate ---
            Date notBefore = leafCert.getNotBefore();
            Date notAfter = leafCert.getNotAfter();
            System.out.println("Leaf notBefore: " + notBefore);
            System.out.println("Leaf notAfter:  " + notAfter);

            // --- Nonce carried in the Apple App Attest leaf extension (OID 1.2.840.113635.100.8.2) ---
            byte[] nonce = extractAppAttestNonce(leafCert);
            System.out.println("Leaf nonce:     " + toHex(nonce));

            // --- App ID, receipt type and environment from the embedded Apple receipt ---
            Map<Integer, byte[]> receiptFields = parseReceiptFields(receipt);
            String appId = asString(receiptFields.get(RECEIPT_FIELD_APP_ID));
            String receiptType = asString(receiptFields.get(RECEIPT_FIELD_TYPE));
            String environment = asString(receiptFields.get(RECEIPT_FIELD_ENVIRONMENT));
            System.out.println("Receipt App ID:      " + appId);
            System.out.println("Receipt Type:        " + receiptType);
            System.out.println("Receipt Environment: " + environment);

            assertNotNull(notBefore);
            assertNotNull(notAfter);
            assertEquals(32, nonce.length);
            assertEquals("64SX4L8SX7.com.merck.wallet", appId);
            assertEquals("ATTEST", receiptType);
            assertEquals("sandbox", environment);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println("");
    }

    @Test
    void checkAndroidAttest() throws Exception {
        byte[] bytes = Base64.getDecoder().decode(androidAttestation);

        String json = new String(bytes, StandardCharsets.UTF_8);

        String[] certs = json
                .replaceAll("^\\s*\\[|\\]\\s*$", "")
                .replace("\"", "")
                .split(",");

        var publicKey = extractPublicKey(certs[0]);
        if (!publicKey.getX().toString().equals(deviceKeyJwk.get("x")) ||
                !publicKey.getY().toString().equals(deviceKeyJwk.get("y")) ||
                !publicKey.getKeyType().toString().equals(deviceKeyJwk.get("kty")) ||
                !publicKey.getCurve().toString().equals(deviceKeyJwk.get("crv"))) {

            throw new IllegalArgumentException(
                    "Public key does not match attestation certificate"
            );
        }

        verifyCertificateChain(certs);

        var seq = getCertData(certs[0]);
        verifyHardwareNonExportableKey(seq);
    }

    public static ECKey publicKeyToJwk(PublicKey publicKey) throws Exception {
        ECKey jwk;

        if (publicKey instanceof java.security.interfaces.ECPublicKey) {
            jwk = new ECKey.Builder(
                    com.nimbusds.jose.jwk.Curve.P_256,
                    (java.security.interfaces.ECPublicKey) publicKey
            ).build();
        } else {
            throw new IllegalArgumentException(
                    "Unsupported public key algorithm: "
                            + publicKey.getAlgorithm()
            );
        }

        return jwk;
    }

    public static ECKey extractPublicKey(String certBase64)
            throws Exception {

        byte[] certBytes = Base64.getDecoder().decode(certBase64);

        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");

        X509Certificate certificate =
                (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(certBytes)
                );

        return publicKeyToJwk(certificate.getPublicKey());
    }

    private static void verifyHardwareNonExportableKey(ASN1Sequence seq)
            throws Exception {
        var elements = seq.getElements();

        if (elements.size() != 8) {
            throw new IllegalArgumentException("Invalid attestation structure");
        }

        ASN1Object attestationVersion = elements.get(0);
        ASN1Object attestationSecurityLevel = elements.get(1);
        ASN1Object keymasterVersion = elements.get(2);
        ASN1Integer keymasterSecurityLevel = (ASN1Integer) elements.get(3);
        ASN1Object attestationChallenge = elements.get(4);
        ASN1Object uniqueId = elements.get(5);
        ASN1Object softwareEnforced = elements.get(6);
        ASN1Object hardwareEnforced = (ASN1Object) elements.get(7);

        int securityLevel = new BigInteger(keymasterSecurityLevel.getValue()).intValue();
        if (securityLevel != TEE && securityLevel != STRONGBOX) {
            throw new SecurityException(
                    "Key is NOT hardware-backed (no TEE / StrongBox)"
            );
        }

        Integer origin = null;
        var hardwareEnforcedElements = ((ASN1Sequence) hardwareEnforced).getElements();
        for (var i = 0; i < hardwareEnforcedElements.size(); i++) {
            var element = hardwareEnforcedElements.get(i);
            var tag = element.getTag();
            if (tag == ORIGIN) {
                var content = ((ASN1TaggedObject) element).getContent();
                if (content.length >= 3 && content[0] == 0x02) {
                    int length = content[1] & 0xFF;
                    byte[] integerBytes = Arrays.copyOfRange(
                            content, 2, 2 + length
                    );
                    origin = new BigInteger(integerBytes).intValueExact();
                }
            }
        }

        if (origin != KM_ORIGIN_GENERATED) {
            throw new SecurityException(
                    "Key was imported (exportable risk)"
            );
        }

    }

    public static ASN1Sequence getCertData(String certBase64) throws Exception {
        byte[] certDer = Base64.getDecoder().decode(certBase64);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certDer)
        );

        byte[] extensionValue = cert.getExtensionValue(ANDROID_ATTESTATION_OID);

        if (extensionValue == null) {
            throw new IllegalArgumentException(
                    "Android attestation extension not found"
            );
        }

        try {
            ASN1Object extensionASN1 = ASN1.INSTANCE.decode(extensionValue);

            if (!(extensionASN1 instanceof ASN1OctetString)) {
                throw new IllegalArgumentException("Invalid extension OCTET STRING");
            }

            ASN1OctetString octetString = (ASN1OctetString) extensionASN1;
            ASN1Object attestationASN1 = ASN1.INSTANCE.decode(octetString.getValue());

            if (!(attestationASN1 instanceof ASN1Sequence)) {
                throw new IllegalArgumentException("Attestation is not ASN.1 SEQUENCE");
            }

            return (ASN1Sequence) attestationASN1;

        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Failed to parse attestation extension", e
            );
        }
    }

    private boolean verifyCertificateChain(String[] certBase64Array) throws Exception {
        if (certBase64Array.length < 2) {
            throw new IllegalArgumentException(
                    "Certificate chain must contain at least 2 certs"
            );
        }

        List<String> certsPem = Arrays.stream(certBase64Array)
                .map((String base64) -> base64ToPem(base64))
                .collect(Collectors.toList());

        for (var i = 0; i < certsPem.size() - 1; i++) {
            var ok = verifyCertSignedBy(certsPem.get(i), certsPem.get(i + 1));
            if (!ok) throw new Error("Certificate " + i + " is NOT signed by certificate" + i + 1);

            var isValid = verifyCertValidity(certsPem.get(i));
            if (!isValid) {
                throw new Error("Certificate " + i + " is expired");
            }
        }

        return true;
    }

    private boolean verifyCertValidity(String certPem) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8))
        );

        Date now = new Date();

        if (now.before(cert.getNotBefore()) || now.after(cert.getNotAfter())) {
            throw new CertificateExpiredException(
                    "Certificate expired or not yet valid: "
                            + cert.getSubjectX500Principal()
            );
        }

        return true;
    }

    private boolean verifyCertSignedBy(String certPem, String issuerCertPem)
            throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8))
        );

        X509Certificate issuerCert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(issuerCertPem.getBytes(StandardCharsets.UTF_8))
        );

        try {
            cert.verify(issuerCert.getPublicKey());
            return true;
        } catch (SignatureException | InvalidKeyException e) {
            return false;
        }
    }

    private String base64ToPem(String base64) {
        String label = "CERTIFICATE";
        StringBuilder formatted = new StringBuilder();

        for (int i = 0; i < base64.length(); i += 64) {
            if (i > 0) {
                formatted.append("\n");
            }

            formatted.append(base64, i, Math.min(i + 64, base64.length()));
        }

        return "-----BEGIN " + label + "-----\n"
                + formatted
                + "\n-----END " + label + "-----\n";
    }

    private boolean verifyAppleAppAttestCertChain(X509Certificate root, X509Certificate intermediate, X509Certificate leaf) {
        try {
            leaf.verify(intermediate.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Invalid leaf signature", e);
        }

        try {
            intermediate.verify(root.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Invalid intermediate signature", e);
        }

        if (!leaf.getIssuerX500Principal().equals(intermediate.getSubjectX500Principal())) {
            throw new IllegalStateException("Leaf issuer mismatch");
        }

        if (!intermediate.getIssuerX500Principal().equals(root.getSubjectX500Principal())) {
            throw new IllegalStateException("Intermediate issuer mismatch");
        }

        // Root validity is intentionally not checked: it mirrors the reference
        // implementation, which only enforces notBefore/notAfter on the chain it is handed.
        for (X509Certificate cert : List.of(leaf, intermediate)) {
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new IllegalStateException("Certificate expired or not yet valid", e);
            }
        }

        return true;
    }

    // Apple App Attest OIDs / receipt field identifiers.
    private static final String APPLE_NONCE_OID = "1.2.840.113635.100.8.2";
    private static final int RECEIPT_FIELD_APP_ID = 2;
    private static final int RECEIPT_FIELD_TYPE = 6;
    private static final int RECEIPT_FIELD_ENVIRONMENT = 7;

    /**
     * Extracts the attestation nonce from the leaf certificate extension
     * {@code 1.2.840.113635.100.8.2}, whose value is {@code SEQUENCE { [1] EXPLICIT OCTET STRING nonce }}.
     */
    private byte[] extractAppAttestNonce(X509Certificate leaf) {
        byte[] extensionValue = leaf.getExtensionValue(APPLE_NONCE_OID);
        if (extensionValue == null) {
            throw new IllegalStateException("Leaf is missing the Apple App Attest nonce extension " + APPLE_NONCE_OID);
        }
        // getExtensionValue wraps the extension in an outer DER OCTET STRING.
        Asn1 outerOctet = new BerParser(extensionValue, 0).parse();
        Asn1 sequence = new BerParser(extensionValue, outerOctet.contentStart).parse();
        Asn1 context1 = sequence.children.get(0);          // [1] EXPLICIT
        Asn1 nonceOctet = context1.children.get(0);        // OCTET STRING
        return Arrays.copyOfRange(extensionValue, nonceOctet.contentStart, nonceOctet.contentEnd);
    }

    /**
     * Parses the Apple receipt (a CMS SignedData, BER-encoded with indefinite lengths) and returns the
     * payload fields keyed by their integer type. Each field is {@code SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }}.
     */
    private Map<Integer, byte[]> parseReceiptFields(byte[] receipt) {
        Asn1 contentInfo = new BerParser(receipt, 0).parse();           // ContentInfo SEQUENCE
        Asn1 content = contentInfo.children.get(1);                     // [0] EXPLICIT content
        Asn1 signedData = content.children.get(0);                      // SignedData SEQUENCE
        Asn1 encapContentInfo = signedData.children.get(2);            // EncapsulatedContentInfo SEQUENCE
        Asn1 eContent = encapContentInfo.children.get(1);              // [0] EXPLICIT eContent
        Asn1 payloadOctet = eContent.children.get(0);                  // OCTET STRING (possibly chunked)

        byte[] payload = octetStringBytes(receipt, payloadOctet);
        Asn1 fieldSet = new BerParser(payload, 0).parse();            // SET OF field

        Map<Integer, byte[]> fields = new HashMap<>();
        for (Asn1 field : fieldSet.children) {
            int type = intValue(payload, field.children.get(0));
            Asn1 value = field.children.get(2);
            fields.put(type, Arrays.copyOfRange(payload, value.contentStart, value.contentEnd));
        }
        return fields;
    }

    /**
     * Returns the content of an OCTET STRING, concatenating the segments of a constructed (chunked)
     * OCTET STRING when the value was BER-encoded in pieces.
     */
    private static byte[] octetStringBytes(byte[] data, Asn1 octet) {
        if (!octet.constructed) {
            return Arrays.copyOfRange(data, octet.contentStart, octet.contentEnd);
        }
        var out = new ByteArrayOutputStream();
        for (Asn1 chunk : octet.children) {
            out.write(data, chunk.contentStart, chunk.contentEnd - chunk.contentStart);
        }
        return out.toByteArray();
    }

    private static int intValue(byte[] data, Asn1 integer) {
        int value = 0;
        for (int i = integer.contentStart; i < integer.contentEnd; i++) {
            value = (value << 8) | (data[i] & 0xFF);
        }
        return value;
    }

    private static String asString(byte[] value) {
        return value == null ? null : new String(value, StandardCharsets.UTF_8);
    }

    private static String toHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Minimal ASN.1 node: enough structure to navigate CMS/receipt and certificate extensions.
     */
    private static final class Asn1 {
        int tag;
        boolean constructed;
        int contentStart;
        int contentEnd;
        final List<Asn1> children = new ArrayList<>();
    }

    /**
     * BER reader supporting both definite and indefinite (0x80) lengths, as used by Apple receipts.
     */
    private static final class BerParser {
        private final byte[] data;
        private int pos;

        BerParser(byte[] data, int pos) {
            this.data = data;
            this.pos = pos;
        }

        Asn1 parse() {
            Asn1 node = new Asn1();
            int tag = data[pos++] & 0xFF;
            node.tag = tag;
            node.constructed = (tag & 0x20) != 0;

            int lengthByte = data[pos++] & 0xFF;
            if (lengthByte == 0x80) {
                // Indefinite length: children run until the end-of-contents marker (00 00).
                node.constructed = true;
                node.contentStart = pos;
                while (!((data[pos] & 0xFF) == 0x00 && (data[pos + 1] & 0xFF) == 0x00)) {
                    node.children.add(parse());
                }
                node.contentEnd = pos;
                pos += 2; // consume end-of-contents
            } else {
                int length;
                if ((lengthByte & 0x80) == 0) {
                    length = lengthByte;
                } else {
                    int numBytes = lengthByte & 0x7F;
                    length = 0;
                    for (int i = 0; i < numBytes; i++) {
                        length = (length << 8) | (data[pos++] & 0xFF);
                    }
                }
                node.contentStart = pos;
                node.contentEnd = pos + length;
                if (node.constructed) {
                    while (pos < node.contentEnd) {
                        node.children.add(parse());
                    }
                } else {
                    pos = node.contentEnd;
                }
            }
            return node;
        }
    }
}
