package nl.trusttech.credentials;

import java.util.Map;

public class CredentialRequestFields {
    public String docType;
    public Map<String, Map<String,Boolean>> nameSpacesAndFields;


    public CredentialRequestFields(String docType, Map<String, Map<String,Boolean>> nameSpacesAndFields) {
        this.docType = docType;
        this.nameSpacesAndFields = nameSpacesAndFields;
    }
}
