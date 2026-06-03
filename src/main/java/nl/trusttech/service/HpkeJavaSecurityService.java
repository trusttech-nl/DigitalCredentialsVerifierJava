package nl.trusttech.service;


import nl.trusttech.crypto.KeyFormattingHelper;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * Base HPKE recipient implementation for:
 * KEM: DHKEM(P-256, HKDF-SHA256), KDF: HKDF-SHA256, AEAD: AES-128-GCM.
 *
 * using only JDK java.security !!!
 */
public final class HpkeJavaSecurityService {

    private static final byte[] HPKE_VERSION_LABEL = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEM_SUITE_ID = concat("KEM".getBytes(StandardCharsets.US_ASCII), i2osp(0x0010, 2));
    private static final byte[] HPKE_SUITE_ID = concat(
            "HPKE".getBytes(StandardCharsets.US_ASCII),
            i2osp(0x0010, 2), // DHKEM(P-256, HKDF-SHA256)
            i2osp(0x0001, 2), // HKDF-SHA256
            i2osp(0x0001, 2)  // AES-128-GCM
    );
    private static final int HASH_LENGTH = 32;
    private static final int KEY_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private HpkeJavaSecurityService() {}

    public static byte[] decryptBaseP256Sha256Aes128Gcm(
            byte[] encapsulatedKey,
            byte[] recipientPrivateKeyDer,
            byte[] recipientPublicKeyDer,
            byte[] info,
            byte[] ciphertextAndTag) {
        try {
            ECPrivateKey recipientPrivateKey =
                    (ECPrivateKey) KeyFormattingHelper.restoreEcPrivateKeyFromDer(recipientPrivateKeyDer);
            ECPublicKey recipientPublicKey =
                    (ECPublicKey) KeyFormattingHelper.restorePublicKeyFromDer(recipientPublicKeyDer);
            ECPublicKey ephemeralPublicKey = decodeUncompressedP256PublicKey(encapsulatedKey);

            byte[] dh = deriveEcdhSharedSecret(recipientPrivateKey, ephemeralPublicKey);
            byte[] kemContext = concat(encapsulatedKey, encodeUncompressedP256PublicKey(recipientPublicKey));
            byte[] sharedSecret = extractAndExpand(dh, kemContext);

            HpkeContext context = setupBaseRecipient(sharedSecret, info);
            return context.open(new byte[0], ciphertextAndTag);
        } catch (Exception e) {
            throw new RuntimeException("HPKE decryption failed: " + e.getMessage(), e);
        }
    }

    public static byte[] deriveEcdhSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    private static HpkeContext setupBaseRecipient(byte[] sharedSecret, byte[] info) throws Exception {
        byte[] pskIdHash = labeledExtract(HPKE_SUITE_ID, new byte[0], "psk_id_hash", new byte[0]);
        byte[] infoHash = labeledExtract(HPKE_SUITE_ID, new byte[0], "info_hash", info);
        byte[] keyScheduleContext = concat(new byte[]{0x00}, pskIdHash, infoHash);

        byte[] secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", new byte[0]);
        byte[] key = labeledExpand(HPKE_SUITE_ID, secret, "key", keyScheduleContext, KEY_LENGTH);
        byte[] baseNonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", keyScheduleContext, NONCE_LENGTH);

        return new HpkeContext(key, baseNonce);
    }

    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) throws Exception {
        byte[] eaePrk = labeledExtract(KEM_SUITE_ID, new byte[0], "eae_prk", dh);
        return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, HASH_LENGTH);
    }

    private static byte[] labeledExtract(byte[] suiteId, byte[] salt, String label, byte[] ikm) throws Exception {
        return hkdfExtract(salt, concat(
                HPKE_VERSION_LABEL,
                suiteId,
                label.getBytes(StandardCharsets.US_ASCII),
                ikm
        ));
    }

    private static byte[] labeledExpand(byte[] suiteId, byte[] prk, String label, byte[] info, int length) throws Exception {
        byte[] labeledInfo = concat(
                i2osp(length, 2),
                HPKE_VERSION_LABEL,
                suiteId,
                label.getBytes(StandardCharsets.US_ASCII),
                info
        );
        return hkdfExpand(prk, labeledInfo, length);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        byte[] actualSalt = salt == null || salt.length == 0 ? new byte[HASH_LENGTH] : salt;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] previous = new byte[0];
        int counter = 1;
        while (output.size() < length) {
            mac.reset();
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            output.write(previous);
            counter++;
        }

        return Arrays.copyOf(output.toByteArray(), length);
    }

    private static ECPublicKey decodeUncompressedP256PublicKey(byte[] encoded) throws Exception {
        if (encoded.length != 65 || encoded[0] != 0x04) {
            throw new IllegalArgumentException("Expected uncompressed P-256 public key (65 bytes)");
        }

        byte[] x = Arrays.copyOfRange(encoded, 1, 33);
        byte[] y = Arrays.copyOfRange(encoded, 33, 65);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(point, ecSpec));
    }

    private static byte[] encodeUncompressedP256PublicKey(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();
        return concat(
                new byte[]{0x04},
                toFixedLength(point.getAffineX(), 32),
                toFixedLength(point.getAffineY(), 32)
        );
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] result = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, result, 0, length);
        } else {
            System.arraycopy(raw, 0, result, length - raw.length, raw.length);
        }
        return result;
    }

    private static byte[] i2osp(int value, int length) {
        byte[] full = ByteBuffer.allocate(4).putInt(value).array();
        return Arrays.copyOfRange(full, full.length - length, full.length);
    }

    private static byte[] concat(byte[]... parts) {
        int len = Arrays.stream(parts).mapToInt(part -> part.length).sum();
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private record HpkeContext(byte[] key, byte[] baseNonce) {
        byte[] open(byte[] aad, byte[] ciphertextAndTag) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, computeNonce(0))
            );
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertextAndTag);
        }

        private byte[] computeNonce(long sequenceNumber) {
            byte[] sequenceBytes = ByteBuffer.allocate(NONCE_LENGTH).putLong(4, sequenceNumber).array();
            byte[] nonce = Arrays.copyOf(baseNonce, baseNonce.length);
            for (int i = 0; i < nonce.length; i++) {
                nonce[i] ^= sequenceBytes[i];
            }
            return nonce;
        }
    }
}
