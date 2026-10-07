package com.github.lechandonga.zerotrustaccessauditjava.web;

import java.util.List;

/**
 * Authenticated caller identity resolved by {@link AuthInterceptor}.
 *
 * @param subject subject; {@code bootstrap-admin} for the local admin token
 * @param roles   roles used for authorization
 * @param jti     credential id, or null for the bootstrap admin path
 * @param keyId   signing key id, or null for the bootstrap admin path
 */
public record Principal(String subject, List<String> roles, String jti, String keyId) {

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean isAdmin() {
        return hasRole("admin");
    }
}

