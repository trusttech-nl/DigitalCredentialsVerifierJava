package nl.trusttech.service;

import kotlinx.io.bytestring.ByteString;
import nl.trusttech.constants.CborConstants;
import nl.trusttech.constants.OpenIdConstants;
import nl.trusttech.credentials.CredentialRequestFields;
import nl.trusttech.crypto.CryptoHelper;
import nl.trusttech.crypto.JweEcDecryptor;
import nl.trusttech.crypto.KeyFormattingHelper;
import nl.trusttech.storage.ISessionStorage;
import nl.trusttech.storage.VerificationSession;
import nl.trusttech.utils.Utils;
import org.multipaz.cbor.*;
import org.multipaz.documenttype.knowntypes.EUPersonalID;
import org.multipaz.mdoc.request.DeviceRequest;
import org.multipaz.mdoc.request.DocRequestInfo;

// can we use it?
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static org.multipaz.cbor.CborArrayKt.buildCborArray;
import static org.multipaz.cbor.CborMapKt.buildCborMap;
import static org.multipaz.mdoc.request.DeviceRequestKt.buildDeviceRequest;

public class VerificationContext {
    private final X509Certificate issuerLeaf;
    private final X509Certificate issuerIntermediate;
    private final X509Certificate issuerRoot;
    private final ISessionStorage sessionStorage;
    private final String verifierOrigin;

    public VerificationContext(X509Certificate issuerLeaf, X509Certificate issuerIntermediate, X509Certificate issuerRoot, ISessionStorage sessionStorage, String verifierOrigin) {
        this.issuerLeaf = issuerLeaf;
        this.issuerIntermediate = issuerIntermediate;
        this.issuerRoot = issuerRoot;
        this.sessionStorage = sessionStorage;
        this.verifierOrigin = verifierOrigin;
    }

    public static class Builder {
        private X509Certificate issuerLeaf;
        private X509Certificate issuerIntermediate;
        private X509Certificate issuerRoot;
        private ISessionStorage sessionStorage;
        private String verifierOrigin;

        public void setIssuerLeaf(X509Certificate issuerLeaf) {
            this.issuerLeaf = issuerLeaf;
        }

        public void setIssuerIntermediate(X509Certificate issuerIntermediates) {
            this.issuerIntermediate = issuerIntermediates;
        }

        public void setIssuerRoot(X509Certificate issuerRoot) {
            this.issuerRoot = issuerRoot;
        }

        public void setSessionStorage(ISessionStorage sessionStorage) {
            this.sessionStorage = sessionStorage;
        }

        public void setVerifierOrigin(String verifierOrigin) {
            this.verifierOrigin = verifierOrigin;
        }

        public VerificationContext Build() {
            return new VerificationContext(issuerLeaf, issuerIntermediate, issuerRoot, sessionStorage, verifierOrigin);
        }
    }


    public Map<String, Object> createProofRequest(
            CredentialRequestFields fields,
            OpenIdConstants.ResponseMode openIdResponseMode,
            OpenIdConstants.CredentialFormat credentialFormat
    ) {
        var sessionId = CryptoHelper.randomBytes(16);
        var sessionIdStr = Base64.getUrlEncoder().withoutPadding().encodeToString(sessionId);

        byte[] asn1DerIssuerCert;
        try {
            asn1DerIssuerCert = issuerLeaf.getEncoded();
        } catch (CertificateException e) {
            throw new RuntimeException("Unable to obtain issuer's certificate from pem");
        }

        DataItem sessionTranscript = new Tstr("");
        DeviceRequest request = buildDeviceRequest(sessionTranscript, null, "1.0", builder -> {

            Map<String, Map<String, Boolean>> namespaces =
                    Map.of(fields.nameSpace, fields.fields);

            // add issuer check in request
            ArrayList<ByteString> issueIdentifier = new ArrayList<>();
            issueIdentifier.add(new ByteString(asn1DerIssuerCert, 0, asn1DerIssuerCert.length));

            Map<String, DataItem> otherInfo = new HashMap<>();
            DocRequestInfo requestInfo = new DocRequestInfo(new ArrayList<>(), issueIdentifier, null, null, null, null, otherInfo);

            builder.addDocRequest(fields.docType, namespaces, requestInfo);
            return null;
        });
        var deviceRequestEncoded = Cbor.INSTANCE.encode(request.toDataItem());
        String deviceRequestEncodedBase64Url = Base64.getUrlEncoder().encodeToString(deviceRequestEncoded);

        VerificationSession verificationSession;
        try {
            verificationSession = CryptoHelper.getEncryptionInfo();
        } catch (Exception e) {
            throw new RuntimeException("Unable to obtain encryption info for because of" + e.getMessage());
        }

        Map<String, String> jwk;
        try {
            ECPublicKey recipientPublicKey = (ECPublicKey) KeyFormattingHelper.restorePublicKeyFromDer(verificationSession.publicKey);
            jwk = KeyFormattingHelper.exportPublicKeyAsJwk(recipientPublicKey);
        } catch (Exception e) {
            throw new RuntimeException("Unable to create ec key from provided byte array" + e.getMessage());
        }

        var openIdRequest = createOpenId4VpRequest(fields,
                verificationSession.nonce,
                jwk,
                openIdResponseMode,
                credentialFormat);

        verificationSession.setOpenidVP(openIdRequest);
        sessionStorage.set(sessionIdStr, verificationSession);

        return Map.of(
                "deviceRequest", deviceRequestEncodedBase64Url,
                "encryptionInfo", verificationSession.encryptionInfoBase64Url,
                "openid4vpRequest", openIdRequest,
                "sessionId", sessionIdStr
        );
    }

    private Map<String, Object> createOpenId4VpRequest(
            CredentialRequestFields fields,
            byte[] nonce,
            Map<String, String> jwk,
            OpenIdConstants.ResponseMode openIdResponseMode,
            OpenIdConstants.CredentialFormat format
    ) {
        String namespace = getNamespaces(fields.docType);
        var nonceBase64Url = Base64.getEncoder().withoutPadding().encodeToString(nonce);

        List<Map<String, Object>> claims;
        Map<String, Object> meta;
        switch (format) {
            case MDOC -> {
                claims = fields.fields.keySet().stream()
                        .map(attributeName -> Map.<String, Object>of(
                                "path", List.of(namespace, attributeName)
                        ))
                        .collect(Collectors.toList());
                meta = Map.of("doctype_value", fields.docType);
            }
            case DS_SD_JWT -> {
                claims = fields.fields.keySet().stream()
                        .map(attributeName -> Map.<String, Object>of(
                                "path", List.of(attributeName)
                        ))
                        .collect(Collectors.toList());
                meta = Map.of("vct_values", List.of(fields.docType));
            }
            default -> {
                throw new RuntimeException("Unsupported credential format");
            }
        }

        Map<String, Object> openId4VpRequest = Map.of(
                "client_metadata", Map.of(
                        "jwks", Map.of(
                                "keys", List.of(jwk)
                        )
                ),
                "dcql_query", Map.of(
                        "credentials", List.of(
                                Map.of(
                                        "id", "cred1",
                                        "claims", claims,
                                        "format", format,
                                        "meta", meta
                                )
                        )
                ),
                "nonce", nonceBase64Url,
                "response_mode", openIdResponseMode,
                "response_type", "vp_token"
        );

        return Map.of(
                "protocol", "openid4vp-v1-unsigned",
                "request", openId4VpRequest
        );
    }

    public static boolean isJwt(String value) {
        if (value == null) {
            return false;
        }

        String[] parts = value.split("\\.");

        return parts.length >= 3;
    }

    public Map<String, Object> verifyAndroid(VerificationSession sessionData, String dcApiJwtEncryptedResponce, Map<String, List<String>> dcApiVpToken) {

        var credValues = new ArrayList<String>();
        if (((Map<String, Object>) sessionData.openidVP.get("request")).get("response_mode") == OpenIdConstants.ResponseMode.DC_API_JWT) {
            if (dcApiJwtEncryptedResponce == null || dcApiJwtEncryptedResponce.isEmpty()) {
                throw new RuntimeException("No dcApiJwtEncryptedResponce provided to handle DC_API_JWT response mode");
            }

            try {
                var privateKey = (ECPrivateKey) KeyFormattingHelper.restoreEcPrivateKeyFromDer(sessionData.privateKey);
                var decrypted = JweEcDecryptor.decryptCompactJwe(dcApiJwtEncryptedResponce, privateKey);

                var credMap = Utils.jsonToMap(decrypted.payload());

                var vpToken = (Map<String, Object>) credMap.get("vp_token");
                ArrayList tokens = (ArrayList) vpToken.get("cred1"); // TODO remove hardcode and get identifier from request
                credValues.add((String) tokens.get(0));

                System.out.println(decrypted);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else if (((Map<String, Object>) sessionData.openidVP.get("request")).get("response_mode") == OpenIdConstants.ResponseMode.DC_API) {

            for (String credname : dcApiVpToken.keySet()) {
                var values = dcApiVpToken.get(credname);
                credValues.addAll(values);
            }
        }

        List<Map<String, Object>> claims = new ArrayList<>();
        for (var credValue : credValues) {
            try {
                var verificationRes = isJwt(credValue) ? verifyAndroidSdJwt(credValue) : verifyAndroidMdoc(credValue, sessionData);
                claims.add(verificationRes);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        return claims.get(0);
    }


    public Map<String, Object> verifyIos(VerificationSession sessionData, String response) {
        byte[] decodedBase64 = Base64.getUrlDecoder().decode(response);
        DataItem decodedCbor = Cbor.INSTANCE.decode(decodedBase64);

        if (!decodedCbor.getAsArray().get(0).getAsTstr().equals("dcapi")) {
            throw new RuntimeException("Not a valid dcapi response");
        }

        if (decodedCbor.getAsArray().get(1).getMajorType() != MajorType.MAP) {
            throw new RuntimeException("position 1 in dcapi array is not a map");
        }

        var enc = decodedCbor.getAsArray().get(1).getAsMap().get(new Tstr("enc")).getAsBstr();
        var cipherText = decodedCbor.getAsArray().get(1).getAsMap().get(new Tstr("cipherText")).getAsBstr();

        // ******************************************************************************************
        // decrypting
        byte[] decrypted;
        try {
            decrypted = decrypt(sessionData, enc, cipherText, verifierOrigin);
        } catch (IOException e) {
            throw new RuntimeException("Decrypt of response failed");
        }

        var deviceResponse = Cbor.INSTANCE.decode(decrypted);
        var documents = deviceResponse.getAsMap().get(new Tstr("documents")).getAsArray();
        var documentMap = documents.get(0).getAsMap(); // in ProofRequest we asking for only one document -> checking only first document

        var docType = documentMap.get(new Tstr("docType")).getAsTstr();
        var docDeviceSigned = documentMap.get(new Tstr("deviceSigned")).getAsMap();
        var docIssuerSigned = documentMap.get(new Tstr("issuerSigned")).getAsMap();
        var docIssuerAuthArr = docIssuerSigned.get(new Tstr("issuerAuth")).getAsArray();

        // ******************************************************************************************
        //  validating issuerAuth - check signature of data block which was signed by issuer key
        boolean isIssuerAuthValid = true;
        try {
            isIssuerAuthValid = validateIssuerAuth(docIssuerAuthArr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // ******************************************************************************************
        //  validating issuer's certificate chain - use the same issuer's certificate key to validate that we as server
        // trust this issuer (list of issuers are hardcoded on server)
        var unprotected = docIssuerAuthArr.get(1).getAsMap();
        var certDer = unprotected.get(CborConstants.U_INT_33).getAsBstr();

        var isCertificateChainValid = true;
        try {
            var leaf = CertificatesService.createCertificateFromDer(certDer);
            CertificatesService.certificateChainValidation(leaf, issuerIntermediate, issuerRoot);
        } catch (Exception e) {
            isCertificateChainValid = false;
        }

        // ******************************************************************************************
        // validating credential date time
        var payloadBuf = docIssuerAuthArr.get(2).getAsBstr();
        var payload = Cbor.INSTANCE.decode(payloadBuf);
        var pValueEncoded = ((Bstr) ((Tagged) payload).getTaggedItem()).getValue();
        var pValue = Cbor.INSTANCE.decode(pValueEncoded);
        var validityInfo = pValue.getAsMap().get(new Tstr("validityInfo")).getAsMap();
        try {
            checkCredentialValidity(validityInfo);
        } catch (Exception e) {
            throw new RuntimeException("Credential expired or not yet valid");
        }

        // ******************************************************************************************
        // obtain device key
        var deviceKeyInfoCborMap = pValue.getAsMap().get(new Tstr("deviceKeyInfo")).getAsMap();
        var deviceKeyCborMap = deviceKeyInfoCborMap.get(new Tstr("deviceKey")).getAsMap();
        var deviceKeyJwk = KeyFormattingHelper.exportCborKeyAsJwk(deviceKeyCborMap);

        // ******************************************************************************************
        // validate device auth -check signature of data block which was signed by device key
        boolean isDeviceAuthValid = true;
        var deviceAuth = docDeviceSigned.get(new Tstr("deviceAuth")).getAsMap();
        var deviceAuthSignatureAr = deviceAuth.get(new Tstr("deviceSignature")).getAsArray();

        var docTypeOfPayload = pValue.get(new Tstr("docType")).getAsTstr();
        var nameSpaces = docDeviceSigned.get(new Tstr("nameSpaces"));

        PublicKey devicePublicKey;
        try {
            devicePublicKey = KeyFormattingHelper.ecJwkToPublicKey(deviceKeyJwk);
        } catch (Exception e) {
            throw new RuntimeException("Unable to convert device jwk key to publicKey");
        }

        try {
            var sessionTranscript = buildDcapiSessionTranscript(sessionData.encryptionInfoBase64Url, verifierOrigin);
            isDeviceAuthValid = validateDeviceAuth(
                    deviceAuthSignatureAr,
                    sessionTranscript,
                    docTypeOfPayload,
                    nameSpaces,
                    devicePublicKey
            );
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Device auth validation failed");
            isDeviceAuthValid = false;
        }

        // ******************************************************************************************
        // obtain data from credential
        var verificationData = getDataFromResponse(docIssuerSigned, EUPersonalID.EUPID_NAMESPACE);

        // ******************************************************************************************
        // validating actual data - compare computed hashed with hashes from credential
        var isValueDigestsValid = validateCredValuesHash(docIssuerSigned, pValue);


        return Map.of(
                "verificationData", verificationData,
                "isIssuerAuthValid", isIssuerAuthValid,
                "isDeviceAuthValid", isDeviceAuthValid,
                "isValueDigestsValid", isValueDigestsValid,
                "isCertificateChainValid", isCertificateChainValid,
                "deviceKeyJwk", deviceKeyJwk
        );

    }

    private boolean validateDeviceAuth(
            List<DataItem> cborSignature,
            DataItem sessionTranscript,
            String docType,
            DataItem nameSpaces,
            PublicKey devicePublicKey
    ) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        var protectedBuf = cborSignature.get(0).getAsBstr();
        var signature = cborSignature.get(3).getAsBstr();

        var deviceAuth = buildCborArray(builder -> {
            builder.add("DeviceAuthentication");
            builder.add(sessionTranscript);
            builder.add(docType);
            builder.add(nameSpaces);
            return null;
        });

        var deviceAuthBytes = Cbor.INSTANCE.encode(deviceAuth);
        var tagged = new Tagged(24, new Bstr(deviceAuthBytes));
        var finalCbor = Cbor.INSTANCE.encode(tagged);

        var SigStructure = buildCborArray(builder -> {
            builder.add("Signature1");
            builder.add(protectedBuf);
            builder.add(new byte[0]);
            builder.add(finalCbor);
            return null;
        });

        var toBeSigned = Cbor.INSTANCE.encode(SigStructure);
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, signature.length);

        var derSignature = KeyFormattingHelper.rawToDer(r, s);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(devicePublicKey);
        verifier.update(toBeSigned);
        var res = verifier.verify(derSignature);
        return res;
    }

    private byte[] decrypt(VerificationSession sessionData, byte[] enc, byte[] cipherText, String origin) throws IOException {
        var sessionTranscript = buildDcapiSessionTranscript(sessionData.encryptionInfoBase64Url, origin);
        var sessionTranscriptCbored = Cbor.INSTANCE.encode(sessionTranscript);

        var decrypted = HpkeJavaSecurityService.decryptBaseP256Sha256Aes128Gcm(
                enc,
                sessionData.privateKey,
                sessionData.publicKey,
                sessionTranscriptCbored,
                cipherText
        );

        return decrypted;


    }

    private DataItem buildDcapiSessionTranscript(String base64EncryptionInfo, String origin) {

        var dcapiInfo = buildCborArray(builder -> {
            builder.add(base64EncryptionInfo);
            builder.add(origin);
            return null;
        });
        var dcapiInfoCborEncoded = Cbor.INSTANCE.encode(dcapiInfo);

        var dcapiInfoHash = CryptoHelper.sha256(dcapiInfoCborEncoded);

        var resDcApi = buildCborArray(builder -> {
            builder.add(CborConstants.NULL);
            builder.add(CborConstants.NULL);

            var dcapiInfoArrayAndHash = buildCborArray(innerBuilder -> {
                innerBuilder.add("dcapi");
                innerBuilder.add(dcapiInfoHash);
                return null;
            });

            builder.add(dcapiInfoArrayAndHash);
            return null;
        });
        return resDcApi;
    }

    private DataItem getHandover(VerificationSession session, String origin, byte[] nonce) {


        var responseModeVP = ((Map<String, Object>) session.getOpenidVP().get("request")).get("response_mode").toString();
        var base64Nonce = Base64.getEncoder().withoutPadding().encodeToString(nonce);

        DataItem handoverData = null;
        if (responseModeVP != null && responseModeVP.equals(OpenIdConstants.ResponseMode.DC_API.toString())) {
            handoverData = buildCborArray(builder -> {
                builder.add(origin);
                builder.add(base64Nonce);
                builder.add(CborConstants.NULL);
                return null;
            });
        } else if (responseModeVP != null && responseModeVP.equals(OpenIdConstants.ResponseMode.DC_API_JWT.toString())) {
            handoverData = buildCborArray(builder -> {
                builder.add(origin);
                builder.add(base64Nonce);

                PublicKey publicKey = null;
                try {
                    publicKey = KeyFormattingHelper.restorePublicKeyFromDer(session.publicKey);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to restore session public key", e);
                }
                var normalizedJwk = KeyFormattingHelper.normalizeEcPublicKeyForJwkThumbprint((ECPublicKey) publicKey);
                var jwkBytes = normalizedJwk.getBytes();
                var handoverInfoHash = CryptoHelper.sha256(jwkBytes);
                builder.add(handoverInfoHash);

                return null;
            });
        }

        var handoverCborEncoded = Cbor.INSTANCE.encode(handoverData);

        var handoverInfoHash = CryptoHelper.sha256(handoverCborEncoded);

        var resDcApi = buildCborArray(builder -> {
            builder.add(CborConstants.NULL);
            builder.add(CborConstants.NULL);

            var dcapiInfoArrayAndHash = buildCborArray(innerBuilder -> {
                innerBuilder.add("OpenID4VPDCAPIHandover");
                innerBuilder.add(handoverInfoHash);
                return null;
            });

            builder.add(dcapiInfoArrayAndHash);
            return null;
        });
        return resDcApi;
    }

    private boolean validateIssuerAuth(List<DataItem> docIssuerAuthArr) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var protectedBuf = docIssuerAuthArr.get(0).getAsBstr();
        var unprotected = docIssuerAuthArr.get(1).getAsMap();
        var payloadBuf = docIssuerAuthArr.get(2).getAsBstr();
        var signature = docIssuerAuthArr.get(3).getAsBstr();

        var certDer = unprotected.get(CborConstants.U_INT_33).getAsBstr();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certDer)
        );
        PublicKey derpublicKey = cert.getPublicKey();


        var SigStructure = buildCborArray(builder -> {
            builder.add(new Tstr("Signature1"));
            builder.add(protectedBuf);
            builder.add(new byte[0]);
            builder.add(payloadBuf);
            return null;
        });
        var toBeSigned = Cbor.INSTANCE.encode(SigStructure);

        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, signature.length);
        var derSignature = KeyFormattingHelper.rawToDer(r, s);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(derpublicKey);
        verifier.update(toBeSigned);
        return verifier.verify(derSignature);
    }

    private void checkCredentialValidity(Map<DataItem, DataItem> validityInfo) throws Exception {
        Date now = new Date();
        var validFromStr = validityInfo.get(new Tstr("validFrom")).getAsTagged().getAsTstr();
        var validUntilStr = validityInfo.get(new Tstr("validUntil")).getAsTagged().getAsTstr();

        Date validFrom = Utils.parseDate(validFromStr);
        Date validUntil = Utils.parseDate(validUntilStr);

        if (now.before(validFrom) || now.after(validUntil)) {
            throw new Exception("Credential expired or not yet valid");
        }
    }

    private Map<String, String> getDataFromResponse(Map<DataItem, DataItem> issuerSigned, String schemaId) {
        var nameSpacesMap = issuerSigned.get(new Tstr("nameSpaces")).getAsMap();
        var nameSpacesAr = nameSpacesMap.get(new Tstr(getNamespaces(schemaId))).getAsArray();

        HashMap<String, String> mapFields = new HashMap<>();
        for (var nameSpace : nameSpacesAr) {
            var credData = Cbor.INSTANCE.decode(((Bstr) ((Tagged) nameSpace).getTaggedItem()).getValue());
            var identifier = credData.get(new Tstr("elementIdentifier")).getAsTstr();
            var value = credData.get(new Tstr("elementValue")).getAsTstr();
            mapFields.put(identifier, value);
        }

        return mapFields;
    }

    private String getNamespaces(String schemaId) {
        switch (schemaId) {
            case "org.iso.18013.5.1.mDL":
                return "org.iso.18013.5.1";
            default:
                return schemaId;
        }
    }


    private boolean validateCredValuesHash(Map<DataItem, DataItem> docIssuerSigned, DataItem pValue) {
        var nameSpacesCborMap = docIssuerSigned.get(new Tstr("nameSpaces")).getAsMap();
        var valueDigests = pValue.getAsMap().get(new Tstr("valueDigests")).getAsMap();
        boolean isValueDigestValid = true;
        for (var key : nameSpacesCborMap.keySet()) {
            var value = nameSpacesCborMap.get(key).getAsArray();
            var digests = valueDigests.get(key).getAsMap();
            for (DataItem item : value) {
                var cborEncodedValue = item.getAsTagged().getAsBstr();
                var isHashValid = checkHash(cborEncodedValue, digests);
                isValueDigestValid = isValueDigestValid && isHashValid;
            }
        }
        return isValueDigestValid;
    }

    private boolean checkHash(byte[] cborEncodedValue, Map<DataItem, DataItem> nameSpaceValueDigest) {
        System.out.println("");
        var value = Cbor.INSTANCE.decode(cborEncodedValue);
        var digestID = value.get(new Tstr("digestID")).getAsNumber();
        var digestIDUInt = value.get(new Tstr("digestID"));
        var random = value.get(new Tstr("random")).getAsBstr();
        var elementIdentifier = value.get(new Tstr("elementIdentifier")).getAsTstr();
        var elementValue = value.get(new Tstr("elementValue")).getAsTstr();

        var mapToHash = buildCborMap(builder -> {
            builder.put("digestID", digestID);
            builder.put("random", random);
            builder.put("elementIdentifier", elementIdentifier);
            builder.put("elementValue", elementValue);

            return null;
        });

        // add tagged cbor tag
        byte[] encodedMap = Cbor.INSTANCE.encode(mapToHash);
        var byteString = new Bstr(encodedMap);
        var tagged = new Tagged(24, byteString);
        byte[] cborToHash = Cbor.INSTANCE.encode(tagged);

        // compute hash
        var computedHash = CryptoHelper.sha256(cborToHash);
        var credValueHash = nameSpaceValueDigest.get(digestIDUInt).getAsBstr();
        var res = Arrays.equals(computedHash, credValueHash);

        return res;
    }

    public Map<String, Object> verifyAndroidMdoc(String credValue, VerificationSession sessionData) {
        var credCbor = Base64.getUrlDecoder().decode(credValue);
        var cborDecoded = Cbor.INSTANCE.decode(credCbor);

        var documents = cborDecoded.getAsMap().get(new Tstr("documents")).getAsArray();
        var documentMap = documents.get(0).getAsMap();

        var docType = documentMap.get(new Tstr("docType")).getAsTstr();
        var docDeviceSigned = documentMap.get(new Tstr("deviceSigned")).getAsMap();
        var docIssuerSigned = documentMap.get(new Tstr("issuerSigned")).getAsMap();
        var docIssuerAuthArr = docIssuerSigned.get(new Tstr("issuerAuth")).getAsArray();

        // the same validation
        // ******************************************************************************************
        //  validating issuerAuth - check signature of data block which was signed by issuer key
        boolean isIssuerAuthValid = true;
        try {
            isIssuerAuthValid = validateIssuerAuth(docIssuerAuthArr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // ******************************************************************************************
        //  validating issuer's certificate chain - use the same issuer's certificate key to validate that we as server
        // trust this issuer (list of issuers are hardcoded on server)
        var unprotected = docIssuerAuthArr.get(1).getAsMap();
        var certDer = unprotected.get(CborConstants.U_INT_33).getAsBstr();

        var isCertificateChainValid = true;
        try {
            var leaf = CertificatesService.createCertificateFromDer(certDer);
            CertificatesService.certificateChainValidation(leaf, issuerIntermediate, issuerRoot);
        } catch (Exception e) {
            isCertificateChainValid = false;
        }

        // ******************************************************************************************
        // validating credential date time
        var payloadBuf = docIssuerAuthArr.get(2).getAsBstr();
        var payload = Cbor.INSTANCE.decode(payloadBuf);
        var pValueEncoded = ((Bstr) ((Tagged) payload).getTaggedItem()).getValue();
        var pValue = Cbor.INSTANCE.decode(pValueEncoded);
        var validityInfo = pValue.getAsMap().get(new Tstr("validityInfo")).getAsMap();
        try {
            checkCredentialValidity(validityInfo);
        } catch (Exception e) {
            throw new RuntimeException("Credential expired or not yet valid");
        }

        // ******************************************************************************************
        // obtain device key
        var deviceKeyInfoCborMap = pValue.getAsMap().get(new Tstr("deviceKeyInfo")).getAsMap();
        var deviceKeyCborMap = deviceKeyInfoCborMap.get(new Tstr("deviceKey")).getAsMap();
        var deviceKeyJwk = KeyFormattingHelper.exportCborKeyAsJwk(deviceKeyCborMap);

        // ******************************************************************************************
        // validate device auth -check signature of data block which was signed by device key
        boolean isDeviceAuthValid = true;
        var deviceAuth = docDeviceSigned.get(new Tstr("deviceAuth")).getAsMap();
        var deviceAuthSignatureAr = deviceAuth.get(new Tstr("deviceSignature")).getAsArray();

        var docTypeOfPayload = pValue.get(new Tstr("docType")).getAsTstr();
        var nameSpaces = docDeviceSigned.get(new Tstr("nameSpaces"));

        PublicKey devicePublicKey;
        try {
            devicePublicKey = KeyFormattingHelper.ecJwkToPublicKey(deviceKeyJwk);
        } catch (Exception e) {
            throw new RuntimeException("Unable to convert device jwk key to publicKey");
        }

        try {
            var sessionTranscript = getHandover(sessionData, verifierOrigin, sessionData.nonce);
            isDeviceAuthValid = validateDeviceAuth(
                    deviceAuthSignatureAr,
                    sessionTranscript,
                    docTypeOfPayload,
                    nameSpaces,
                    devicePublicKey
            );
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Device auth validation failed");
            isDeviceAuthValid = false;
        }

        // ******************************************************************************************
        // obtain data from credential
        var verificationData = getDataFromResponse(docIssuerSigned, EUPersonalID.EUPID_NAMESPACE);

        // ******************************************************************************************
        // validating actual data - compare computed hashed with hashes from credential
        var isValueDigestsValid = validateCredValuesHash(docIssuerSigned, pValue);

        return Map.of(
                "verificationData", verificationData,
                "isIssuerAuthValid", isIssuerAuthValid,
                "isDeviceAuthValid", isDeviceAuthValid,
                "isValueDigestsValid", isValueDigestsValid,
                "isCertificateChainValid", isCertificateChainValid,
                "deviceKeyJwk", deviceKeyJwk
        );
    }

    public Map<String, Object> verifyAndroidSdJwt(String credValue) throws Exception {
        List<Map<String, Object>> verificationData = new ArrayList<>();
        Map<String, String> deviceKeyJwk = new LinkedHashMap<>();

        SDJWT sdjwt = SDJWT.parse(credValue);
        SignedJWT jwt = SignedJWT.parse(sdjwt.getCredentialJwt());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        // Extract did:jwk
        String iss = claims.getIssuer();
        if (iss == null || !iss.startsWith("did:jwk:")) {
            throw new RuntimeException("Unsupported issuer");
        }
        String encoded = iss.split(":")[2];
        String jwkJson = new String(
                Base64.getUrlDecoder().decode(encoded),
                StandardCharsets.UTF_8
        );
        ECKey issuerKey = ECKey.parse(jwkJson);

        // Verify signature
        boolean verified = jwt.verify(new ECDSAVerifier(issuerKey.toECPublicKey()));
        boolean isIssuerAuthValid = verified;

        if (!verified) {
            throw new RuntimeException("Invalid signature");
        }

        // Decode disclosed claims
        SDObjectDecoder decoder = new SDObjectDecoder();

        Map<String, Object> decoded =
                decoder.decode(
                        claims.getClaims(),
                        sdjwt.getDisclosures()
                );


        List<String> requiredClaimKeys = new ArrayList<>();
        requiredClaimKeys.add("family_name");
        requiredClaimKeys.add("given_name");
        for (String claimKey : requiredClaimKeys) {
            Map<String, Object> item =
                    new HashMap<>();

            item.put("name", claimKey);
            item.put("value", decoded.get(claimKey));

            verificationData.add(item);
        }

        Map<String, Object> cnf = (Map<String, Object>) decoded.get("cnf");
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");

        deviceKeyJwk.put("kty", jwk.get("kty").toString());
        deviceKeyJwk.put("crv", jwk.get("crv").toString());
        deviceKeyJwk.put("x", jwk.get("x").toString());
        deviceKeyJwk.put("y", jwk.get("y").toString());

        SignedJWT kbJwt = SignedJWT.parse(sdjwt.getBindingJwt());
        ECKey deviceKey = ECKey.parse(deviceKeyJwk.toString());
        boolean kbJwtVerified = kbJwt.verify(new ECDSAVerifier(deviceKey.toECPublicKey()));
        boolean isDeviceAuthValid = kbJwtVerified;

        var disclosures = sdjwt.getDisclosures();
        var sd = claims.getClaims().get("_sd");
        boolean isValueDigestsValid = disclosures.stream().allMatch(x -> ((ArrayList) sd).contains(x.digest()));

        return Map.of(
                "isIssuerAuthValid", isIssuerAuthValid,
                "isDeviceAuthValid", isDeviceAuthValid,
                "isValueDigestsValid", isValueDigestsValid,
                "deviceKeyJwk", deviceKeyJwk,
                "verificationData", verificationData
                //  TODO "isCertificateChainValid", isCertificateChainValid,
        );
    }
}
