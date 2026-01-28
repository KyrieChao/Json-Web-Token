package keyMinter.spi;

import jakarta.annotation.Resource;
import keyMinter.api.KeyMinter;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component("key-minter")
public class KeyMinterHealthIndicator implements HealthIndicator {
    @Resource
    private KeyMinter keyMinter;

    public Health health() {
        boolean exists = keyMinter.keyPairExists();
        String activeKeyId = keyMinter.getActiveKeyId();
        Path keyPath = keyMinter.getKeyPath();
        boolean dirReadable = keyPath != null && Files.exists(keyPath) && Files.isDirectory(keyPath) && Files.isReadable(keyPath);
        int cacheSize = keyMinter.getCacheSize();
        String algoInfo = keyMinter.getAlgorithmInfo();
        Health.Builder builder = exists ? Health.up() : Health.down();
        builder.withDetail("activeKeyId", activeKeyId)
                .withDetail("keyDir", keyPath != null ? keyPath.toString() : "null")
                .withDetail("dirReadable", dirReadable)
                .withDetail("cacheSize", cacheSize)
                .withDetail("algorithm", algoInfo);
        return builder.build();
    }
}
