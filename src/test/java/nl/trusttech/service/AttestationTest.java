package nl.trusttech.service;

import nl.trusttech.TestConstants;
import nl.trusttech.constants.OpenIdConstants;
import org.junit.jupiter.api.Test;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.Tstr;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
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

import static org.junit.jupiter.api.Assertions.*;

public class AttestationTest {
    public static String iosAttestation = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZBBMwggQPMIIDlaADAgECAgYBoaq8MvYwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjYxMTA0MDgwMzQyWhcNMjYxMTA3MDgwMzQyWjCBkTFJMEcGA1UEAwxAZmRjM2IyZjY1NDk0MzEyZDY0MGI5YjAxODFiMzg4ZjEyZTk1M2M3YjNiODE2OGZlOTg5OWM2YWUyZDE4NWVkNTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThWwdN377fLMOF3fVK2l6l5T1Z3Xy/1uCYGAu2AaaENvnQmX2wUPVY1SOnATQGY1vRv1biSby2KQnd8PB7qClSo4ICGDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwFAYDVR0lBA0wCwYJKoZIhvdjZAQYMHkGCSqGSIb3Y2QIBQRsMGqkAwIBCr+JMAMCAQC/iTEDAgEAv4kyAwIBAL+JMwMCAQC/iTQdBBs2NFNYNEw4U1g3LmNvbS5tZXJjay53YWxsZXS/iTYDAgEEv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBAKoDAgEAMIHTBgkqhkiG92NkCAcEgcUwgcK/ingIBAYyNi42LjK/iFADAgECv4p5CQQHMS4wLjI0OL+KewcEBTIzRzkwv4p8CAQGMjYuNi4yv4p9CAQGMjYuNi4yv4p+AwIBAL+KfwMCAQC/iwADAgEAv4sBAwIBAL+LAgMCAQC/iwMDAgEAv4sEAwIBAb+LBQMCAQC/iwoPBA0yMy43LjkwLjAuMCwwv4sLDwQNMjMuNy45MC4wLjAsML+LDA8EDTIzLjcuOTAuMC4wLDC/iAIKBAhpcGhvbmVvczAzBgkqhkiG92NkCAIEJjAkoSIEIJfMdWJcdp6yx1Cso8mhYCMUcplc1lFDq+1sdv8zMMwKMFgGCSqGSIb3Y2QIBgRLMEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/MAoGCCqGSM49BAMCA2gAMGUCMCn+mjcdI/LPHvwPvX+KkaGKjv2qDTJaVHKW8e2pKl9cp3xVOYmvqvtMLvxNXNjzmQIxALM86ZbaGIQyOTnk1n7Uv/55K1E28g1tLoWaEPyNdqJAQCEpBpq9JMHJnro/J+C2YVkCRzCCAkMwggHIoAMCAQICEAm6xeG8QBrZ1FOVvDgaCFQwCgYIKoZIzj0EAwMwUjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzOTU1WhcNMzAwMzEzMDAwMDAwWjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK5bN6B3TXmyNY9A59HyJibxwl/vF4At6rOCalmHT/jSrRUleJqiZgQZEki2PLlnBp6Y02O9XjcPv6COMp6Ac6mF53Ruo1mi9m8p2zKvRV4hFljVZ6+eJn6yYU3CGmbOmaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSskRBTM72+aEH/pwyp5frq5eWKoTAdBgNVHQ4EFgQUPuNdHAQZqcm0MfiEdNbh4Vdy45swDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2kAMGYCMQC7voiNc40FAs+8/WZtCVdQNbzWhyw/hDBJJint0fkU6HmZHJrota7406hUM/e2DQYCMQCrOO3QzIHtAKRSw7pE+ZNjZVP+zCl/LrTfn16+WkrKtplcS4IN+QQ4b3gHu1iUObdncmVjZWlwdFkPeDCABgkqhkiG9w0BBwKggDCAAgEBMQ8wDQYJYIZIAWUDBAIBBQAwgAYJKoZIhvcNAQcBoIAkgASCA+gxggUvMCMCAQICAQEEGzY0U1g0TDhTWDcuY29tLm1lcmNrLndhbGxldDCCBB0CAQMCAQEEggQTMIIEDzCCA5WgAwIBAgIGAaGqvDL2MAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MTEwNDA4MDM0MloXDTI2MTEwNzA4MDM0MlowgZExSTBHBgNVBAMMQGZkYzNiMmY2NTQ5NDMxMmQ2NDBiOWIwMTgxYjM4OGYxMmU5NTNjN2IzYjgxNjhmZTk4OTljNmFlMmQxODVlZDUxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4VsHTd++3yzDhd31StpepeU9Wd18v9bgmBgLtgGmhDb50Jl9sFD1WNUjpwE0BmNb0b9W4km8tikJ3fDwe6gpUqOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDB5BgkqhkiG92NkCAUEbDBqpAMCAQq/iTADAgEAv4kxAwIBAL+JMgMCAQC/iTMDAgEAv4k0HQQbNjRTWDRMOFNYNy5jb20ubWVyY2sud2FsbGV0v4k2AwIBBL+JNwMCAQC/iTkDAgEAv4k6AwIBAL+JOwMCAQCqAwIBADCB0wYJKoZIhvdjZAgHBIHFMIHCv4p4CAQGMjYuNi4yv4hQAwIBAr+KeQkEBzEuMC4yNDi/insHBAUyM0c5ML+KfAgEBjI2LjYuMr+KfQgEBjI2LjYuMr+KfgMCAQC/in8DAgEAv4sAAwIBAL+LAQMCAQC/iwIDAgEAv4sDAwIBAL+LBAMCAQG/iwUDAgEAv4sKDwQNMjMuNy45MC4wLjAsML+LCw8EDTIzLjcuOTAuMC4wLDC/iwwPBA0yMy43LjkwLjAuMCwwv4gCCgQIaXBob25lb3MwMwYJKoZIhvdjZAgCBCYwJKEiBCCXzHViXHaessdQrKPJoWAjFHKZXNZRQ6vtbHb/MzDMCjBYBgkqhkiG92NkCAYESzBJo0cERTBDDAIxMTA9MAoMA29rZKEDAQH/MAkMAm9hoQMBAf8wCwwEb3NnbqEDAQH/MAsMBG9kZWyhAwEB/zAKDANvY2uhAwEB/zAKBggqhkjOPQQDAgNoADBlAjApBIIBS/6aNx0j8s8e/A+9f4qRoYqO/aoNMlpUcpbx7akqX1ynfFU5ia+q+0wu/E1c2POZAjEAszzpltoYhDI5OeTWftS//nkrUTbyDW0uhZoQ/I12okBAISkGmr0kwcmeuj8n4LZhMCgCAQQCAQEEIBohoukQCFwdl1MdLTz64RsgT7EYLnyWkBvi6xRgteLaMGACAQUCAQEEWE5wYjlvTHZOeEphZlduWlRWVER5aTdUc05NZEZIWUxudWU3VnZmQzRVQUl5dUFvb0RuZkFQbU5hNGc4RVVaMWtNeFlQOHM4QnZ6N2IzcE0vSkthU1l3PT0wDgIBBgIBAQQGQVRURVNUMA8CAQcCAQEEB3NhbmRib3gwHAIBDAIBAQQUMjAyNi0xMS0wNVQwODowMzo0M1owHAIBFQIBAQQUMjAyNy0wMi0wM1QwODowMzo0M1oAAAAAAACggDCCA64wggNUoAMCAQICEGYCOIAAFCb3XYsOFSxfbkMwCgYIKoZIzj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjYwMTIwMjAyMTA5WhcNMjcwMjE4MTg1ODM5WjBaMTYwNAYDVQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOxiuzsUZrYpTUbRARLSjA5lXtM29W4Uf4Bpv7eKN77D6sMNqAqQfRG4AbVgOVopngIkH80iAkUOLIM6qTJ3cVqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFDRViXB0YA4i0rpnz6VbacIj8cooMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0gAMEUCIBxnl7mCRdHW3HIEt5sCPK/4e/Lv+JN91yDEXorkZcLrAiEA/MhZhM7JoSzChqnUknb98NL2Jdx1/Hz4h0Vpe+YeqrQwggL5MIICf6ADAgECAhBW+4PUK/+NwzeZI7Varm69MAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE5MDMyMjE3NTMzM1oXDTM0MDMyMjAwMDAwMFowfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSzmO9fYaxqygKOxzhr/sElICRrPYx36bLKDVvREvhIeVX3RKNjbqCfJW+Sfq+M8quzQQZ8S9DJfr0vrPLg366o4H3MIH0MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFNkX/ktnkDhLkvTbztVXgBQLjz3JMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIDBAIFADAKBggqhkjOPQQDAwNoADBlAjEAjW+mn6Hg5OxbTnOKkn89eFOYj/TaH1gew3VK/jioTCqDGhqqDaZkbeG5k+jRVUztAjBnOyy04eg3B3fL1ex2qBo6VTs/NWrIxeaSsOFhvoBJaeRfK6ls4RECqsxh2Ti3c0owggJDMIIByaADAgECAggtxfyI0sVLlTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xNDA0MzAxODE5MDZaFw0zOTA0MzAxODE5MDZaMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmOkvPUBypO2TInKBExzdEJXxxaNOcdwUFtkO5aYFKndke19OONO7HES1f/UftjJiXcnphFtPME8RWgD9WFgMpfUPLE0HRxN12peXl28xXO0rnXsgO9i5VNlemaQ6UQoxo0IwQDAdBgNVHQ4EFgQUu7DeoVgziJqkipnevr3rr9rLJKswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWXhpdNBjZ7e/0bA4ARku437JGEcUP/eZ6jKGma87CA9Sc9ZPGdLhq36ojFQIwbWaKEMrUDdRPzY1DPrSKY6UzbuNt2he3ZB/IUyb5iGJ0OQsXW8tRqAzoGAPnorIoAAAxgf4wgfsCAQEwgZAwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEGYCOIAAFCb3XYsOFSxfbkMwDQYJYIZIAWUDBAIBBQAwCgYIKoZIzj0EAwIESDBGAiEA4UsZ0Aslh+XmFld7yfp3CKXVg0rmRAkusXyLPAbWwKcCIQC0+XEPQxdiUcNQUO8G19DxcchO3P9JxRlzawlA9lO+jgAAAAAAAGhhdXRoRGF0YVikCt8mwCgeOt/aV8zNF4XaAjomtPYSzm3yjZo4R9cLtadAAAAAAGFwcGF0dGVzdGRldmVsb3AAIP3DsvZUlDEtZAubAYGziPEulTx7O4Fo/piZxq4tGF7VpQECAyYgASFYIOFbB03fvt8sw4Xd9UraXqXlPVndfL/W4JgYC7YBpoQ2Ilgg+dCZfbBQ9VjVI6cBNAZjW9G/VuJJvLYpCd3w8HuoKVI=";

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

    /** Minimal ASN.1 node: enough structure to navigate CMS/receipt and certificate extensions. */
    private static final class Asn1 {
        int tag;
        boolean constructed;
        int contentStart;
        int contentEnd;
        final List<Asn1> children = new ArrayList<>();
    }

    /** BER reader supporting both definite and indefinite (0x80) lengths, as used by Apple receipts. */
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
