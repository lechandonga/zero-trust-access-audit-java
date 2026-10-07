package com.github.lechandonga.zerotrustaccessauditjava.authz;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Holds the current {@link Policy} behind an immutable reference.
 *
 * <p>Updates are all-or-nothing: callers construct and validate the complete
 * replacement policy first, then publish it in a single volatile write.
 * Concurrent readers either observe the previous policy or the new one for
 * the whole evaluation — interleaving rules from two versions is impossible.
 */
@Component
public class PolicyStore {

    private volatile Policy current = Policy.denyAll(0);

    public Policy current() {
        return current;
    }

    /**
     * Publishes a fully prepared replacement policy atomically.
     *
     * @return the published policy version
     */
    public synchronized long publish(List<Policy.Rule> rules) {
        Policy next = new Policy(current.version() + 1, rules);
        this.current = next;
        return next.version();
    }
}

