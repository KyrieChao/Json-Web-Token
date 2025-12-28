package key_minter.domain.ports;

import key_minter.model.Algorithm;

/**
 * @since 2025
 * Port for Hardware Security Module operations.
 */
public interface HsmPort {
    byte[] generateKey(Algorithm algorithm);
    boolean storeKey(byte[] keyMaterial, String slot);
    boolean attest(String slot);
}
