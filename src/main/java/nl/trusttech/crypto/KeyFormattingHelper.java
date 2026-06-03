package nl.trusttech.crypto;

import kotlin.Pair;
import nl.trusttech.constants.CborConstants;
import nl.trusttech.utils.Utils;
import org.multipaz.cbor.DataItem;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.multipaz.cbor.CborMapKt.buildCborMap;

public class KeyFormattingHelper {
    public static byte[] deriveEcdhSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    private static Pair<String,String> getEcPoints(ECPublicKey publicKey){
        ECPublicKey ecKey = publicKey;
        ECPoint point = ecKey.getW();

        byte[] x = Utils.toBytes32(point.getAffineX());
        byte[] y = Utils.toBytes32(point.getAffineY());
        var xBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(x);
        var yBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(y);

        return new Pair<>(xBase64,yBase64);
    }

    public static Map<String,String> exportPublicKeyAsJwk(ECPublicKey publicKey) {
        var points = getEcPoints(publicKey);

        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        var kid = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", points.getFirst());
        jwk.put("y", points.getSecond());
        jwk.put("use", "enc");
        jwk.put("alg", "ECDH-ES");
        jwk.put("kid", kid);

        return jwk;
    }

    public static String normalizeEcPublicKeyForJwkThumbprint(ECPublicKey publicKey) {
        var points = getEcPoints(publicKey);

        return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + points.getFirst() + "\",\"y\":\"" + points.getSecond() + "\"}";
    }

    public static Map<String, String> exportCborKeyAsJwk( Map<DataItem, DataItem> deviceKeyCborMap ) {
        var x = deviceKeyCborMap.get(CborConstants.N_INT_MINUS_2).getAsBstr();
        var y = deviceKeyCborMap.get(CborConstants.N_INT_MINUS_3).getAsBstr();
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(x));
        jwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(y));
        return jwk;
    }

    public static DataItem exportPublicKeyAsCose(PublicKey publicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;
        ECPoint point = ecKey.getW();

        byte[] x = Utils.toBytes32(point.getAffineX());
        byte[] y = Utils.toBytes32(point.getAffineY());

        return buildCborMap(mapBuilder -> {
            mapBuilder.put(1, 2);
            mapBuilder.put(-1, 1);
            mapBuilder.put(-2, x);
            mapBuilder.put(-3, y);
            return null;
        });
    }

    public static PublicKey ecJwkToPublicKey(Map<String, String> jwk) throws Exception {
        byte[] xBytes = Base64.getUrlDecoder().decode(jwk.get("x"));
        byte[] yBytes = Base64.getUrlDecoder().decode(jwk.get("y"));

        ECPoint point = new ECPoint(
                new BigInteger(1, xBytes),
                new BigInteger(1, yBytes)
        );

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(new ECPublicKeySpec(point, ecSpec));
    }

    public static PrivateKey restoreEcPrivateKeyFromDer(byte[] encodedPrivateKey) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey restorePublicKeyFromDer(byte[] encodedPublicKey) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    public static X509Certificate GetX509CertificateFromPem(String pem) throws CertificateException {
        String cleaned = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(decoded));
    }

    public static byte[] rawToDer(byte[] r, byte[] s) throws IOException {
        byte[] rEnc = encodeInt(r);
        byte[] sEnc = encodeInt(s);

        int totalLen = rEnc.length + sEnc.length;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        out.write(totalLen);
        out.write(rEnc);
        out.write(sEnc);

        return out.toByteArray();
    }

    private static byte[] encodeInt(byte[] buf) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if ((buf[0] & 0x80) != 0) {
            out.write(0x02);
            out.write(buf.length + 1);
            out.write(0x00);
        } else {
            out.write(0x02);
            out.write(buf.length);
        }

        out.write(buf);
        return out.toByteArray();
    }
}
