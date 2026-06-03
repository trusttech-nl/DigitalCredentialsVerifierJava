package nl.trusttech.credentials;

import java.util.Map;

public class CredentialRequestFields {
    public String docType;
    public String nameSpace;
    public Map<String, Boolean> fields;

    public CredentialRequestFields(String docType, String nameSpace, Map<String, Boolean> fields) {
        this.docType = docType;
        this.nameSpace = nameSpace;
        this.fields = fields;
    }
}
