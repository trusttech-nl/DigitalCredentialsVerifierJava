package nl.trusttech.crypto;


import nl.trusttech.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * JWE decryption for ECDH-ES / ECDH-ES+A*KW using only JDK crypto APIs (RFC 7516 / 7518).
 */
public final class JweEcDecryptor {

    private JweEcDecryptor() {}

    public record JweDecryptResult(String payload, Map<String, Object> header) {}

    public static JweDecryptResult decryptCompactJwe(String compactJwe, ECPrivateKey recipientPrivateKey) {
        try {
            String[] parts = compactJwe.split("\\.", -1);
            if (parts.length != 5) {
                throw new IllegalArgumentException("Compact JWE must have 5 parts, got " + parts.length);
            }

            String encodedHeader = parts[0];
            byte[] encryptedKey = base64UrlDecode(parts[1]);
            byte[] iv = base64UrlDecode(parts[2]);
            byte[] ciphertext = base64UrlDecode(parts[3]);
            byte[] authTag = base64UrlDecode(parts[4]);

            Map<String, Object> header = Utils.jsonToMap(
                    new String(base64UrlDecode(encodedHeader), StandardCharsets.UTF_8));

            String alg = requireString(header, "alg");
            String enc = requireString(header, "enc");
            @SuppressWarnings("unchecked")
            Map<String, Object> epk = (Map<String, Object>) header.get("epk");
            if (epk == null) {
                throw new IllegalArgumentException("JWE header missing epk");
            }

            ECPublicKey ephemeralPublicKey = (ECPublicKey) KeyFormattingHelper.ecJwkToPublicKey(toStringMap(epk));
            byte[] sharedSecret = KeyFormattingHelper.deriveEcdhSharedSecret(recipientPrivateKey, ephemeralPublicKey);

            SecretKey cek = resolveContentEncryptionKey(
                    alg, enc, header, sharedSecret, encryptedKey);

            byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
            byte[] plaintext = decryptAesGcm(enc, cek, iv, ciphertext, authTag, aad);

            return new JweDecryptResult(new String(plaintext, StandardCharsets.UTF_8), header);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("JWE decryption failed: " + e.getMessage(), e);
        }
    }

    private static SecretKey resolveContentEncryptionKey(
            String alg,
            String enc,
            Map<String, Object> header,
            byte[] sharedSecret,
            byte[] encryptedKey) throws Exception {

        if ("ECDH-ES".equals(alg)) {
            int cekBits = encCekBitLength(enc);
            return deriveDirectCek(sharedSecret, enc, header, cekBits);
        }

        if (alg.startsWith("ECDH-ES+")) {
            int kekBits = kwKeyBitLength(alg);
            SecretKey kek = deriveKek(sharedSecret, alg, header, kekBits);
            byte[] cekBytes = unwrapAesKey(encryptedKey, kek, alg);
            return new SecretKeySpec(cekBytes, "AES");
        }

        throw new IllegalArgumentException("Unsupported JWE alg: " + alg);
    }

    private static SecretKey deriveDirectCek(
            byte[] sharedSecret,
            String enc,
            Map<String, Object> header,
            int cekBits) throws Exception {
        byte[] derived = concatKdf(sharedSecret, cekBits, buildOtherInfo(enc, header));
        return new SecretKeySpec(derived, "AES");
    }

    private static SecretKey deriveKek(
            byte[] sharedSecret,
            String alg,
            Map<String, Object> header,
            int kekBits) throws Exception {
        byte[] derived = concatKdf(sharedSecret, kekBits, buildOtherInfo(alg, header));
        return new SecretKeySpec(derived, "AES");
    }

    private static byte[] buildOtherInfo(String algorithmId, Map<String, Object> header) {
        byte[] apu = decodeOptionalBase64Url(header.get("apu"));
        byte[] apv = decodeOptionalBase64Url(header.get("apv"));
        int keyDataLenBits = algorithmId.startsWith("ECDH-ES+")
                ? kwKeyBitLength(algorithmId)
                : encCekBitLength(algorithmId);

        return concat(
                encodeDataWithLength(algorithmId.getBytes(StandardCharsets.US_ASCII)),
                encodeDataWithLength(apu),
                encodeDataWithLength(apv),
                encodeInt32(keyDataLenBits),
                new byte[0]
        );
    }

    private static byte[] concatKdf(byte[] sharedSecret, int keyDataLenBits, byte[] otherInfo) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        int hashLen = digest.getDigestLength();
        int reps = (int) Math.ceil((double) keyDataLenBits / (hashLen * 8));
        int keyDataLenBytes = keyDataLenBits / 8;

        ByteBuffer derived = ByteBuffer.allocate(reps * hashLen);
        for (int round = 1; round <= reps; round++) {
            digest.reset();
            digest.update(encodeInt32(round));
            digest.update(sharedSecret);
            digest.update(otherInfo);
            derived.put(digest.digest());
        }

        byte[] out = new byte[keyDataLenBytes];
        derived.flip();
        derived.get(out);
        return out;
    }

    private static byte[] decryptAesGcm(
            String enc,
            SecretKey cek,
            byte[] iv,
            byte[] ciphertext,
            byte[] authTag,
            byte[] aad) throws Exception {
        int tagBits = 128;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagBits, iv);
        cipher.init(Cipher.DECRYPT_MODE, cek, gcmSpec);
        cipher.updateAAD(aad);

        byte[] cipherInput = concat(ciphertext, authTag);
        return cipher.doFinal(cipherInput);
    }

    private static byte[] unwrapAesKey(byte[] encryptedKey, SecretKey kek, String alg) throws Exception {
        if (encryptedKey.length == 0) {
            throw new IllegalArgumentException("Missing JWE encrypted key for key-wrapping mode");
        }
        if (!alg.startsWith("ECDH-ES+")) {
            throw new IllegalArgumentException("Unsupported key wrap alg: " + alg);
        }
        Cipher cipher = Cipher.getInstance("AESWrap");
        cipher.init(Cipher.UNWRAP_MODE, kek);
        SecretKey cek = (SecretKey) cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
        return cek.getEncoded();
    }

    private static int encCekBitLength(String enc) {
        return switch (enc) {
            case "A128GCM" -> 128;
            case "A192GCM" -> 192;
            case "A256GCM" -> 256;
            default -> throw new IllegalArgumentException("Unsupported enc: " + enc);
        };
    }

    private static int kwKeyBitLength(String alg) {
        return switch (alg) {
            case "ECDH-ES+A128KW" -> 128;
            case "ECDH-ES+A192KW" -> 192;
            case "ECDH-ES+A256KW" -> 256;
            default -> throw new IllegalArgumentException("Unsupported KW alg: " + alg);
        };
    }

    private static byte[] encodeDataWithLength(byte[] data) {
        byte[] value = data != null ? data : new byte[0];
        return concat(encodeInt32(value.length), value);
    }

    private static byte[] encodeInt32(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private static byte[] concat(byte[]... parts) {
        int len = Arrays.stream(parts).mapToInt(p -> p.length).sum();
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static byte[] base64UrlDecode(String value) {
        if (value == null || value.isEmpty()) {
            return new byte[0];
        }
        return Base64.getUrlDecoder().decode(value);
    }

    private static byte[] decodeOptionalBase64Url(Object value) {
        if (value == null) {
            return new byte[0];
        }
        if (value instanceof String s) {
            return s.isEmpty() ? new byte[0] : base64UrlDecode(s);
        }
        throw new IllegalArgumentException("apu/apv must be a Base64URL string");
    }

    private static String requireString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String s)) {
            throw new IllegalArgumentException("JWE header missing or invalid: " + key);
        }
        return s;
    }

    private static Map<String, String> toStringMap(Map<String, Object> map) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (var entry : map.entrySet()) {
            if (entry.getValue() instanceof String s) {
                out.put(entry.getKey(), s);
            }
        }
        return out;
    }
}
