package key_minter.domain.ports;

/**
 * @since 2025
 * Trace context for logging correlation.
 */
public interface TraceContextPort {
    String traceId();
    String userId();
}

