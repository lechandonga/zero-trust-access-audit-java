package com.github.lechandonga.zerotrustaccessauditjava.config;

import com.github.lechandonga.zerotrustaccessauditjava.crypto.SystemClock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties(ZtaaProperties.class)
public class AppConfig {

    @Bean
    public SystemClock systemClock() {
        return new SystemClock();
    }

    /**
     * Resolves the bootstrap admin token: explicit configuration wins,
     * otherwise a random one is generated and reported once via stdout
     * (it is never written into the application log afterwards).
     */
    @Bean
    public BootstrapAdminToken bootstrapAdminToken(ZtaaProperties properties) {
        String configured = properties.adminToken() == null ? "" : properties.adminToken().trim();
        if (!configured.isEmpty()) {
            return new BootstrapAdminToken(configured, false);
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String generated = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        System.out.println("[ztaa] No ztaa.admin-token configured. Generated bootstrap admin token "
                + "(shown once, save it): " + generated);
        return new BootstrapAdminToken(generated, true);
    }

    public record BootstrapAdminToken(String value, boolean generated) {
    }
}

