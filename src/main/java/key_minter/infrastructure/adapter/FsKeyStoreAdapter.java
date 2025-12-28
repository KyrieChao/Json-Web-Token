package key_minter.infrastructure.adapter;

import key_minter.domain.ports.KeyStorePort;
import key_minter.model.KeyVersion;
import key_minter.model.Algorithm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @since 2025
 * Filesystem-backed keystore adapter (placeholder).
 */
public class FsKeyStoreAdapter implements KeyStorePort {
    @Override
    public Optional<byte[]> loadSecret(Path versionDir, Algorithm algorithm) {
        try {
            Path file = versionDir.resolve("secret.key");
            if (Files.exists(file)) {
                return Optional.of(Files.readAllBytes(file));
            }
        } catch (Exception ignored) {
        }
        return Optional.empty();
    }

    @Override
    public boolean saveSecret(Path versionDir, Algorithm algorithm, byte[] data) {
        try {
            Files.createDirectories(versionDir);
            Files.write(versionDir.resolve("secret.key"), data);
            Files.writeString(versionDir.resolve("algorithm.info"), algorithm.name());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public List<KeyVersion> listAll(Path baseDir) {
        // Placeholder: return empty list for now
        return new ArrayList<>();
    }

    @Override
    public boolean markActive(Path versionDir) {
        try {
            Files.createFile(versionDir.resolve(".active"));
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
