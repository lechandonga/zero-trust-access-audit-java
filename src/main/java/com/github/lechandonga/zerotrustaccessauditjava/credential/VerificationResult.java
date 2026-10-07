package com.github.lechandonga.zerotrustaccessauditjava.credential;

/**
 * 凭证校验结果：要么有效并携带负载，要么无效并携带可区分的拒绝原因。
 */
public sealed interface VerificationResult {

    record Valid(CredentialClaims claims) implements VerificationResult {
    }

    record Invalid(RejectionReason reason, String detail) implements VerificationResult {
    }

    default boolean isValid() {
        return this instanceof Valid;
    }
}
