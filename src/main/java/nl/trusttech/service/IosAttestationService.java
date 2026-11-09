package nl.trusttech.service;

import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.Tstr;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.*;

public class IosAttestationService {
    // Apple App Attest OIDs / receipt field identifiers.
    private static final String APPLE_NONCE_OID = "1.2.840.113635.100.8.2";
    private static final int RECEIPT_FIELD_APP_ID = 2;
    private static final int RECEIPT_FIELD_TYPE = 6;
    private static final int RECEIPT_FIELD_ENVIRONMENT = 7;
    private static final String APPLE_APP_ATTESTATION_ROOT_CA = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem";

    public static Map<String, Object> checkIosAttest(String iosAttestation) {
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

            InputStream rootStream = URI.create(APPLE_APP_ATTESTATION_ROOT_CA).toURL().openStream();
            var rootCert = (X509Certificate) factory.generateCertificate(rootStream);

            if (!verifyAppleAppAttestCertChain(rootCert, intermdiateCert, leafCert)) {
                throw new Exception("Certificate chain is not valid");
            }

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

            Map<String, Object> attestObject = Map.of(
                    "appId", appId,
                    "receiptType", receiptType,
                    "environment", environment,
                    "notBefore", notBefore,
                    "notAfter", notAfter,
                    "nonce", nonce
            );
            return attestObject;
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verifyAppleAppAttestCertChain(X509Certificate root, X509Certificate intermediate, X509Certificate leaf) {
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

    /**
     * Extracts the attestation nonce from the leaf certificate extension
     * {@code 1.2.840.113635.100.8.2}, whose value is {@code SEQUENCE { [1] EXPLICIT OCTET STRING nonce }}.
     */
    private static byte[] extractAppAttestNonce(X509Certificate leaf) {
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
    private static Map<Integer, byte[]> parseReceiptFields(byte[] receipt) {
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
