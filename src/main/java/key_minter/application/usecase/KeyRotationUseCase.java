package key_minter.application.usecase;

import key_minter.domain.ports.KeyStorePort;
import key_minter.model.Algorithm;

import java.nio.file.Path;

/**
 * @since 2025
 * Key rotation orchestration use case.
 */
public class KeyRotationUseCase {
    private final KeyStorePort store;

    public KeyRotationUseCase(KeyStorePort store) {
        this.store = store;
    }

    public boolean rotate(Path dir, Algorithm algorithm) {
        // Placeholder for rotation logic that will use Ports; legacy path remains active
        return false;
    }
}
