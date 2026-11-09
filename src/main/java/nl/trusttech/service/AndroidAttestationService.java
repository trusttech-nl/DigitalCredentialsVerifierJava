package nl.trusttech.service;

import com.nimbusds.jose.jwk.ECKey;
import nl.trusttech.models.AndroidAttestationResult;
import org.multipaz.asn1.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class AndroidAttestationService {
    private static final String ANDROID_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    // Security levels
    private static final int SOFTWARE = 0;
    private static final int TEE = 1;
    private static final int STRONGBOX = 2;

    // Key origin
    private static final int KM_ORIGIN_GENERATED = 0;
    private static final int ORIGIN = 702;

    public static AndroidAttestationResult checkAndroidAttest(String androidAttestation, Map<String, String> deviceKeyJwk) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(androidAttestation);

        String json = new String(bytes, StandardCharsets.UTF_8);

        String[] certs = json
                .replaceAll("^\\s*\\[|\\]\\s*$", "")
                .replace("\"", "")
                .split(",");

        AndroidAttestationResult result = new AndroidAttestationResult();

        try {
            publicKeyMatched(deviceKeyJwk, certs[0]);
            result.publicKeyMatched = true;
            result.keyAlgorithm = deviceKeyJwk.get("kty").toString();
            result.keyCurve = deviceKeyJwk.get("crv").toString();
        } catch (Exception e) {
            result.publicKeyMatched = false;
            result.errors.add(e.getMessage());
        }

        try {
            verifyCertificateChain(certs);
            result.certificateChainValid = true;
        } catch (Exception e) {
            result.certificateChainValid = false;
            result.errors.add(e.getMessage());
        }

        try {
            var seq = getCertData(certs[0]);
            var keysObj = verifyHardwareNonExportableKey(seq);
            result.hardwareBacked = true;
            result.securityLevel = (String) keysObj.get("securityLevel");
            result.keyOrigin = (String) keysObj.get("keyOrigin");
            result.osVersion = (String) keysObj.get("osVersion");
            result.osPatchLevel = (String) keysObj.get("osPatchLevel");
            result.packageName = (String) keysObj.get("packageName");
            result.creationDateTime = (Instant) keysObj.get("creationDate");
        } catch (Exception e) {
            result.hardwareBacked = false;
            result.errors.add(e.getMessage());
        }

        return result;
    }

    private static void publicKeyMatched(Map<String, String> deviceKeyJwk, String cert) throws Exception {
        var publicKey = extractPublicKey(cert);
        if (!publicKey.getX().toString().equals(deviceKeyJwk.get("x")) ||
                !publicKey.getY().toString().equals(deviceKeyJwk.get("y")) ||
                !publicKey.getKeyType().toString().equals(deviceKeyJwk.get("kty")) ||
                !publicKey.getCurve().toString().equals(deviceKeyJwk.get("crv"))) {
            throw new IllegalArgumentException(
                    "Public key does not match attestation certificate"
            );
        }
    }

    private static ECKey publicKeyToJwk(PublicKey publicKey) throws Exception {
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

    private static ECKey extractPublicKey(String certBase64)
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

    private static Map<String, Object> verifyHardwareNonExportableKey(ASN1Sequence seq) {
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
        Map<String, Object> keysObj = new HashMap<>();

        if (securityLevel == TEE) {
            keysObj.put("securityLevel", "TEE");
        } else if (securityLevel == STRONGBOX) {
            keysObj.put("securityLevel", "STRONGBOX");
        } else {
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
            if (tag == 705) {
                var content = ((ASN1TaggedObject) element).getContent();
                BigInteger version = new BigInteger(
                        Arrays.copyOfRange(content, 2, content.length)
                );
                int v = version.intValue();

                int major = v / 10000;
                int minor = (v / 100) % 100;
                int patch = v % 100;

                keysObj.put("osVersion", major + "." + minor + "." + patch);
            }
            if (tag == 706) {
                byte[] content = ((ASN1TaggedObject) element).getContent();

                BigInteger patchLevel = new BigInteger(
                        Arrays.copyOfRange(content, 2, content.length)
                );

                int value = patchLevel.intValue();

                int year = value / 100;
                int month = value % 100;
                keysObj.put("osPatchLevel", year + "-" + month);
            }
        }

        if (origin != KM_ORIGIN_GENERATED) {
            throw new SecurityException(
                    "Key was imported (exportable risk)"
            );
        } else {
            keysObj.put("keyOrigin", "KM_ORIGIN_GENERATED");
        }

        var softwareEnforcedElements = ((ASN1Sequence) softwareEnforced).getElements();
        for (var i = 0; i < softwareEnforcedElements.size(); i++) {
            var element = softwareEnforcedElements.get(i);
            var tag = element.getTag();
            if (tag == 709) {
                byte[] content = ((ASN1TaggedObject) element).getContent();
                String packageName = new String(
                        Arrays.copyOfRange(content, 10, 32),
                        StandardCharsets.UTF_8
                );
                keysObj.put("packageName", packageName);
            }
            if (tag == 701) {
                byte[] content = ((ASN1TaggedObject) element).getContent();

                BigInteger timestamp = new BigInteger(
                        Arrays.copyOfRange(content, 2, content.length)
                );
                Instant creationDate = Instant.ofEpochMilli(
                        timestamp.longValueExact()
                );
                keysObj.put("creationDate", creationDate);
            }
        }

        return keysObj;
    }

    private static ASN1Sequence getCertData(String certBase64) throws Exception {
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

    public static void verifyCertificateChain(String[] certBase64Array) throws Exception {
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

    }

    private static boolean verifyCertValidity(String certPem) throws Exception {

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

    private static boolean verifyCertSignedBy(String certPem, String issuerCertPem)
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

    private static String base64ToPem(String base64) {
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
}
