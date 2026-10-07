package com.github.lechandonga.zerotrustaccessauditjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Local zero-trust settings.
 *
 * @param adminToken bootstrap token for management endpoints; when blank a
 *                   random token is generated at startup and printed once
 *                   (tokens never appear in any later log line)
 */
@ConfigurationProperties(prefix = "ztaa")
public record ZtaaProperties(String adminToken) {
}

