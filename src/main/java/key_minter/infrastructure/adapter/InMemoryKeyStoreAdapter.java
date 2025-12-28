package key_minter.infrastructure.adapter;

import key_minter.domain.ports.KeyStorePort;
import key_minter.model.KeyVersion;
import key_minter.model.Algorithm;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 2025
 * Simple in-memory keystore adapter for dev/testing.
 */
public class InMemoryKeyStoreAdapter implements KeyStorePort {
    private final Map<Path, byte[]> store = new ConcurrentHashMap<>();
    private final Map<Path, KeyVersion> meta = new ConcurrentHashMap<>();

    @Override
    public Optional<byte[]> loadSecret(Path versionDir, Algorithm algorithm) {
        return Optional.ofNullable(store.get(versionDir));
    }

    @Override
    public boolean saveSecret(Path versionDir, Algorithm algorithm, byte[] data) {
        store.put(versionDir, Arrays.copyOf(data, data.length));
        meta.putIfAbsent(versionDir, new KeyVersion(versionDir.getFileName().toString(), algorithm, versionDir.toString()));
        return true;
    }

    @Override
    public List<KeyVersion> listAll(Path baseDir) {
        List<KeyVersion> list = new ArrayList<>();
        meta.forEach((p, v) -> {
            if (p.startsWith(baseDir)) list.add(v);
        });
        return list;
    }

    @Override
    public boolean markActive(Path versionDir) {
        KeyVersion v = meta.get(versionDir);
        if (v != null) {
            v.setActive(true);
            return true;
        }
        return false;
    }
}
