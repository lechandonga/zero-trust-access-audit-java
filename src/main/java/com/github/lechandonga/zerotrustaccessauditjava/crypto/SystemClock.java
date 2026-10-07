package com.github.lechandonga.zerotrustaccessauditjava.crypto;

import java.time.Clock;
import java.time.Instant;

/**
 * Mutable clock abstraction used everywhere instead of {@link Instant#now()}.
 * Tests advance the clock deterministically to hit expiry/grace boundaries.
 */
public class SystemClock {

    private volatile Clock clock = Clock.systemUTC();

    public Instant now() {
        return Instant.now(clock);
    }

    public long epochMilli() {
        return now().toEpochMilli();
    }

    /** Test support: pin or advance the clock. Production code never calls this. */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /** Test support: restore wall-clock behaviour. */
    public void reset() {
        this.clock = Clock.systemUTC();
    }
}

