package nl.trusttech.credentials;

import org.multipaz.documenttype.knowntypes.DrivingLicense;
import org.multipaz.documenttype.knowntypes.EUPersonalID;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class CredentialRequestHelper {
    public static String TRUST_TECH_NAMESPACE = "nl.trusttech.metadata";
    public static String TRUST_TECH_ATTESTATION_ATTRIBUTE = "attestation";
    public static String TRUST_TECH_PLATFORM_ATTRIBUTE = "platform";

    /**
     * Creates a credential request containing the family name and given name fields
     * for the specified credential type.
     *
     * If you want to add extra fields to validation you could use org.multipaz.documenttype.knowntypes.EUPersonalID
     * to check additional fields and add then to CredentialRequestFields.fields map
     *
     * @param type the credential type ({@link CredentialTypes#EUPid} or {@link CredentialTypes#DriverLicense})
     * @return a {@link CredentialRequestFields} with the doctype, namespace, and requested attributes
     * @throws RuntimeException if the credential type is not supported
     */
    public static CredentialRequestFields createEUPIDRequest(CredentialTypes type, boolean includeAttestation) {
        CredentialRequestFields credentialRequestFields;
        switch (type) {
            case EUPid -> {
                var attrFamilyName = EUPersonalID.INSTANCE.getDocumentType().getMdocDocumentType()
                        .getNamespaces().get(EUPersonalID.EUPID_NAMESPACE)
                        .getDataElements().get("family_name").getAttribute().getIdentifier();

                var attrGivenName = EUPersonalID.INSTANCE.getDocumentType().getMdocDocumentType()
                        .getNamespaces().get(EUPersonalID.EUPID_NAMESPACE)
                        .getDataElements().get("given_name").getAttribute().getIdentifier();

                var namespacesAndValues = new HashMap<String, Map<String,Boolean>>();
                namespacesAndValues.put(EUPersonalID.EUPID_NAMESPACE, Map.of(attrFamilyName, true, attrGivenName, true));

                if (includeAttestation) {
                    namespacesAndValues.put(TRUST_TECH_NAMESPACE, Map.of(TRUST_TECH_ATTESTATION_ATTRIBUTE, true, TRUST_TECH_PLATFORM_ATTRIBUTE, true));
                }

                credentialRequestFields = new CredentialRequestFields(
                        EUPersonalID.EUPID_DOCTYPE,
                        namespacesAndValues);
            }

            case DriverLicense -> {
                var attrFamilyName = DrivingLicense.INSTANCE.getDocumentType().getMdocDocumentType()
                        .getNamespaces().get(DrivingLicense.MDL_NAMESPACE)
                        .getDataElements().get("family_name").getAttribute().getIdentifier();

                var attrGivenName = DrivingLicense.INSTANCE.getDocumentType().getMdocDocumentType()
                        .getNamespaces().get(DrivingLicense.MDL_NAMESPACE)
                        .getDataElements().get("given_name").getAttribute().getIdentifier();

                var namespacesAndValues = new HashMap<String, Map<String,Boolean>>();
                namespacesAndValues.put(DrivingLicense.MDL_NAMESPACE, Map.of(attrFamilyName, true, attrGivenName, true));

                if (includeAttestation) {
                    namespacesAndValues.put(TRUST_TECH_NAMESPACE, Map.of(TRUST_TECH_ATTESTATION_ATTRIBUTE, true, TRUST_TECH_PLATFORM_ATTRIBUTE, true));
                }

                credentialRequestFields = new CredentialRequestFields(
                        DrivingLicense.MDL_DOCTYPE,
                        namespacesAndValues);
            }
            default -> throw new RuntimeException("Unsupported credential type");
        }

        return credentialRequestFields;
    }
}
