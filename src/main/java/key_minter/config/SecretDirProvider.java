package key_minter.config;

import lombok.extern.slf4j.Slf4j;
import key_minter.auth.factory.JwtFactory;

import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public final class SecretDirProvider {
    private static volatile Path DEFAULT_BASE_DIR = Paths.get(System.getProperty("user.home"), ".chao");

    private SecretDirProvider() {
    }

    public static Path getDefaultBaseDir() {
        return DEFAULT_BASE_DIR;
    }

    public static void setDefaultBaseDir(Path baseDir) {
        if (baseDir != null) {
            log.info("Setting default base directory to {}", baseDir);
            DEFAULT_BASE_DIR = baseDir.normalize();
            JwtFactory.clearCache();
        }
    }
}
