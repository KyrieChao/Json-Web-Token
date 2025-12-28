package key_minter.application.usecase;

import key_minter.domain.ports.KeyStorePort;
import key_minter.model.KeyVersion;

import java.nio.file.Path;
import java.util.List;

/**
 * @since 2025
 * Query keys metadata use case.
 */
public class KeyQueryUseCase {
    private final KeyStorePort store;

    public KeyQueryUseCase(KeyStorePort store) {
        this.store = store;
    }

    public List<KeyVersion> list(Path baseDir) {
        return store.listAll(baseDir);
    }
}
