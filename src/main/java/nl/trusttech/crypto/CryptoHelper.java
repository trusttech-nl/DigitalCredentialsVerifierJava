package nl.trusttech.crypto;

import nl.trusttech.storage.VerificationSession;
import org.multipaz.cbor.Cbor;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.multipaz.cbor.CborArrayKt.buildCborArray;
import static org.multipaz.cbor.CborMapKt.buildCborMap;

public final class CryptoHelper {

    private CryptoHelper() {}

    public static KeyPair generateKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }


    public static VerificationSession getEncryptionInfo() throws Exception {
        KeyPair keyPair = generateKeys();

        var coseDataItem = KeyFormattingHelper.exportPublicKeyAsCose(keyPair.getPublic());
        var nonce = randomBytes(64);

        var encriptionInfoArray = buildCborArray( builder -> {
            builder.add("dcapi");

            var encriptionInfo = buildCborMap(mapBuilder -> {
                mapBuilder.put("nonce", nonce);
                mapBuilder.put("recipientPublicKey", coseDataItem);
                return null;
            });
            builder.add(encriptionInfo);
            return null;
        });


        var encriptionInfoArrayEncoded = Cbor.INSTANCE.encode(encriptionInfoArray);
        var encriptionInfoArrayEncodeBase64 = Base64.getUrlEncoder().encodeToString(encriptionInfoArrayEncoded);

        return new VerificationSession(
                encriptionInfoArrayEncodeBase64,
                keyPair.getPrivate().getEncoded(),
                keyPair.getPublic().getEncoded(),
                nonce);
    }


    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }


}
