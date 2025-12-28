package key_minter.domain.ports;

import key_minter.model.Algorithm;

/**
 * @since 2025
 * Port for generic KMS operations (software or cloud KMS).
 */
public interface KmsPort {
    byte[] generateKeyMaterial(Algorithm algorithm, int strength);
    byte[] sign(Algorithm algorithm, byte[] payload);
    boolean verify(Algorithm algorithm, byte[] payload, byte[] signature);
}
