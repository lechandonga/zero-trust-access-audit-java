package com.github.lechandonga.zerotrustaccessauditjava.authz;

import java.util.List;
import java.util.Map;

/**
 * A resource access request carrying the attributes policies match against.
 *
 * @param action       e.g. {@code read}, {@code write}
 * @param resourceType e.g. {@code document}, {@code audit}
 * @param resourceId   stable resource identifier
 * @param environment  deployment environment label, e.g. {@code prod}
 * @param tags         free-form resource tags
 * @param attributes   additional resource attributes (owner, classification...)
 */
public record ResourceRequest(String action,
                              String resourceType,
                              String resourceId,
                              String environment,
                              List<String> tags,
                              Map<String, String> attributes) {

    public ResourceRequest {
        tags = tags == null ? List.of() : List.copyOf(tags);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}

