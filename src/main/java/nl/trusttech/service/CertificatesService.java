package nl.trusttech.service;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.*;

public class CertificatesService {

    public static X509Certificate createCertificateFromDer(byte[] certDer) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return  (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certDer)
        );
    }

    public static void certificateChainValidation(X509Certificate leaf,
                                               X509Certificate intermediate,
                                               X509Certificate root) throws Exception {

        // 1. Trust anchors (root CA)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(root, null));


        // 2. Build cert store (intermediates + leaf)
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(leaf);
        if (intermediate != null) {
            certs.add(intermediate);
        }

        CertStore certStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(certs)
        );

        // 3. PKIX параметры
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false); // можно включить CRL/OCSP позже
        params.addCertStore(certStore);

        // 4. Build certificate path starting from leaf (must include all intermediates, excluding root trust anchor)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        List<X509Certificate> pathCerts = new ArrayList<>();
        pathCerts.add(leaf);
        if (intermediate != null) {
            pathCerts.add(intermediate);
        }
        CertPath certPath = cf.generateCertPath(pathCerts);

        // 5. Validator
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        try {
            validator.validate(certPath, params);

        } catch (CertPathValidatorException e) {
            System.out.println("Certificate chain is invalid");
            throw e;
        }

        var chain = List.of(leaf, intermediate, root);

        // date time validity
        for (X509Certificate cert : chain) {
            checkCertValidity(cert);
        }

        // todo if needed method could be expanded to check
        // 1. aki/ski
        // 2. key usage

        System.out.println("Certificate chain is valid");
    }


    private static void checkCertValidity(X509Certificate cert) throws Exception {
        Date now = new Date();

        Date notBefore = cert.getNotBefore();
        Date notAfter  = cert.getNotAfter();

        if (now.before(notBefore) || now.after(notAfter)) {
            throw new Exception("Certificate expired or not yet valid");
        }
    }
}
