package com.github.lechandonga.zerotrustaccessauditjava.credential;

/**
 * Distinguishable rejection reasons for credential verification.
 * Each constant maps to a stable wire code so clients and audit records
 * can tell failure modes apart.
 */
public enum CredentialRejection {

    MALFORMED("malformed"),
    SIGNATURE_MISMATCH("signature_mismatch"),
    EXPIRED("expired"),
    REVOKED("revoked"),
    UNKNOWN_KEY("unknown_key");

    private final String code;

    CredentialRejection(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}

