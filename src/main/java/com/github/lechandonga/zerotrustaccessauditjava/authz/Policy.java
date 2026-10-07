package com.github.lechandonga.zerotrustaccessauditjava.authz;

import java.util.List;

/**
 * Immutable authorization policy. A policy is an ordered list of rules;
 * the first matching rule decides and absence of any match means DENY.
 *
 * @param version monotonically increasing version, returned for observability
 * @param rules   ordered rules; empty lists inside a rule act as wildcards
 */
public record Policy(long version, List<Rule> rules) {

    public enum Effect {ALLOW, DENY}

    /**
     * A rule matches when the caller has at least one listed role (or the
     * role list is empty) and the resource/action attributes intersect the
     * configured values (empty lists match anything).
     */
    public record Rule(String name, Effect effect,
                       List<String> roles,
                       List<String> actions,
                       List<String> resourceTypes,
                       List<String> environments,
                       List<String> tags) {

        public Rule {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("rule name is required");
            }
            if (effect == null) {
                throw new IllegalArgumentException("rule effect is required");
            }
            roles = roles == null ? List.of() : List.copyOf(roles);
            actions = actions == null ? List.of() : List.copyOf(actions);
            resourceTypes = resourceTypes == null ? List.of() : List.copyOf(resourceTypes);
            environments = environments == null ? List.of() : List.copyOf(environments);
            tags = tags == null ? List.of() : List.copyOf(tags);
        }
    }

    public Policy {
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    public static Policy denyAll(long version) {
        return new Policy(version, List.of());
    }
}

