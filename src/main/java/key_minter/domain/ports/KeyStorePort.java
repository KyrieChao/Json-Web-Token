package key_minter.domain.ports;

import key_minter.model.KeyVersion;
import key_minter.model.Algorithm;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * @since 2025
 * Port for key storage operations (filesystem, KMS-backed keystore, DB, etc.)
 */
public interface KeyStorePort {
    Optional<byte[]> loadSecret(Path versionDir, Algorithm algorithm);
    boolean saveSecret(Path versionDir, Algorithm algorithm, byte[] data);
    List<KeyVersion> listAll(Path baseDir);
    boolean markActive(Path versionDir);
}
