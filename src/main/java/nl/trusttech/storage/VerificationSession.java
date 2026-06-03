package nl.trusttech.storage;

import java.util.Map;

public class VerificationSession {
    public String encryptionInfoBase64Url;
    public byte[] privateKey;
    public byte[] publicKey;
    public byte[] nonce;
    public Map<String, Object> openidVP;

    public VerificationSession(String encryptionInfoBase64Url, byte[] encryptedPrivateKey, byte[] encryptedPublicKey, byte[] nonce) {
        this.encryptionInfoBase64Url = encryptionInfoBase64Url;
        this.privateKey = encryptedPrivateKey;
        this.publicKey = encryptedPublicKey;
        this.nonce = nonce;
    }

    public Map<String, Object> getOpenidVP() {
        return openidVP;
    }

    public void setOpenidVP(Map<String, Object> openidVP) {
        this.openidVP = openidVP;
    }
}
