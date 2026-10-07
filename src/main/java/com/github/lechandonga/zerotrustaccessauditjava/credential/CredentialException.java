package com.github.lechandonga.zerotrustaccessauditjava.credential;

/**
 * Thrown when a credential cannot be verified. The rejection reason is
 * machine-readable and never carries credential material.
 */
public class CredentialException extends RuntimeException {

    private final CredentialRejection rejection;

    public CredentialException(CredentialRejection rejection, String message) {
        super(message);
        this.rejection = rejection;
    }

    public CredentialRejection rejection() {
        return rejection;
    }
}

