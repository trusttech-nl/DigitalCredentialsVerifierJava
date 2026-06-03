package nl.trusttech.storage;

public interface ISessionStorage {
    void set(String key, VerificationSession value);
    VerificationSession get(String key);
    void remove(String key);
}
