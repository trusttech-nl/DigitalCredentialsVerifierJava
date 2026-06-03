package nl.trusttech.constants;

public class OpenIdConstants {
    public enum ResponseMode {
        DC_API("dc_api"),
        DC_API_JWT("dc_api.jwt");

        private final String value;

        ResponseMode(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    public enum CredentialFormat {
        MDOC("mso_mdoc"),
        DS_SD_JWT("dc+sd-jwt");

        private final String value;

        CredentialFormat(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return value;
        }
    }
}
