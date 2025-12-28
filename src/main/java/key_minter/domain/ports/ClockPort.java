package key_minter.domain.ports;

import java.time.Instant;

/**
 * @since 2025
 * Time provider abstraction for testability.
 */
public interface ClockPort {
    Instant now();
}

