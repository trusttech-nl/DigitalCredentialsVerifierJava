package nl.trusttech.service;

import nl.trusttech.TestConstants;
import nl.trusttech.constants.OpenIdConstants;
import nl.trusttech.storage.ISessionStorage;
import nl.trusttech.storage.VerificationSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class VerificationContextTest {
    private VerificationContext verificationContext;

    private X509Certificate issuerLeaf;
    private X509Certificate issuerIntermediate;
    private X509Certificate issuerRoot;
    private ISessionStorage sessionStorage;

    @BeforeEach
    void setUp() {
        verificationContext = new VerificationContext(issuerLeaf, issuerIntermediate, issuerRoot, sessionStorage, TestConstants.ORIGIN);
    }

    Map<String, Object> mdlClaimsTestData() {
        Map<String, Object> obj = new HashMap<>();
        List<Map<String, Object>> claims = new ArrayList<>();

        Map<String, Object> item1 = new HashMap<>();
        item1.put("path", List.of("given_name"));

        Map<String, Object> item2 = new HashMap<>();
        item2.put("path", List.of("family_name"));

        claims.add(item1);
        claims.add(item2);

        obj.put("claims", claims);

        return obj;
    }

    VerificationSession mdlSessionTestData(OpenIdConstants.ResponseMode responseMode, OpenIdConstants.CredentialFormat credentialFormat) {
        var encryptionInfoBase64Url = ""; // TODO
        var docType = TestConstants.DOC_TYPE;
        String snonce = TestConstants.NONCE;
        byte[] nonce = Base64.getDecoder().decode(snonce);

        var session = new VerificationSession(encryptionInfoBase64Url, null, null, nonce);

        Map<String, Object> meta = credentialFormat == OpenIdConstants.CredentialFormat.MDOC ?
                Map.of("doctype_value", docType) :
                Map.of("vct_values", List.of(docType));

        var claims = mdlClaimsTestData();

        Map<String, Object> openId4VpRequest = Map.of(
                "client_metadata", Map.of(
                        "jwks", Map.of() // TODO
                ),
                "dcql_query", Map.of(
                        "credentials", List.of(
                                Map.of(
                                        "id", "cred1",
                                        "claims", claims,
                                        "format", credentialFormat,
                                        "meta", meta
                                )
                        )
                ),
                "nonce", snonce,
                "response_mode", responseMode,
                "response_type", "vp_token"
        );

        var openidVP = Map.of(
                "protocol", "openid4vp-v1-unsigned",
                "request", openId4VpRequest
        );

        session.setOpenidVP(openidVP);

        return session;
    }

    @Test
    void shouldVerifyAndroidSdJwtDcApiSuccessfully() {
        var token = TestConstants.ANDROID_SD_JWT_DC_API;
        Map<String, List<String>> vpToken = new HashMap<>();
        vpToken.put("cred1", List.of(token));

        var session = mdlSessionTestData(OpenIdConstants.ResponseMode.DC_API, OpenIdConstants.CredentialFormat.DS_SD_JWT);

        Map<String, Object> result =
                verificationContext.verifyAndroid(
                        session,
                        null,
                        vpToken
                );


        assertEquals(true, result.get("isIssuerAuthValid"));
        assertEquals(true, result.get("isDeviceAuthValid"));
        assertEquals(true, result.get("isValueDigestsValid"));

//        assertEquals(true, result.get("isCertificateChainValid")); TODO

        List<Map<String, Object>> verificationData =
                (List<Map<String, Object>>) result.get("verificationData");

        assertNotNull(verificationData);
        assertFalse(verificationData.isEmpty());
    }

    @Test
    void shouldVerifyAndroidMdocDcApiSuccessfully() {
        var token = TestConstants.ANDROID_MDOC_DC_API;
        Map<String, List<String>> vpToken = new HashMap<>();
        vpToken.put("cred1", List.of(token));

        var session = mdlSessionTestData(OpenIdConstants.ResponseMode.DC_API, OpenIdConstants.CredentialFormat.MDOC);

        Map<String, Object> result =
                verificationContext.verifyAndroid(
                        session,
                        null,
                        vpToken
                );


        assertEquals(true, result.get("isIssuerAuthValid"));
        assertEquals(true, result.get("isDeviceAuthValid"));
        assertEquals(true, result.get("isValueDigestsValid"));

//        assertEquals(true, result.get("isCertificateChainValid")); TODO

        Map<String, Object> verificationData = (Map<String, Object>) result.get("verificationData");

        assertNotNull(verificationData);
        assertFalse(verificationData.isEmpty());
    }
}
