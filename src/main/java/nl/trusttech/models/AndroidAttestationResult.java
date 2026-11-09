package nl.trusttech.models;

import java.time.Instant;
import java.util.List;

public class AndroidAttestationResult {
    public boolean certificateChainValid;
    public boolean publicKeyMatched;
    public boolean hardwareBacked;

    public String securityLevel;
    public String keyOrigin;

    public String keyAlgorithm;
    public String keyCurve;

    public String osVersion;
    public String osPatchLevel;

    public String packageName;
    public Instant creationDateTime;

    public List<String> errors;
}