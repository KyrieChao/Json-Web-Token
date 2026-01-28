package keyMinter.internal.core.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import keyMinter.config.KeyMinterConfigHolder;
import keyMinter.config.KeyMinterProperties;
import keyMinter.internal.core.JwtAlgo;
import keyMinter.internal.rotation.KeyRotation;
import keyMinter.internal.security.SecureByteArray;
import keyMinter.model.Algorithm;
import keyMinter.model.JwtProperties;
import keyMinter.model.KeyVersion;
import keyMinter.spi.SecretDirProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

@Getter
@Slf4j
public class HmacJwt extends AbstractJwtAlgo {
    private final Map<String, SecureByteArray> versionSecrets = new ConcurrentHashMap<>();
    private static final String KEY_VERSION_PREFIX = "hmac-v";
    private SecureByteArray currentSecret;

    private static Path getDefaultHmacDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("hmac-keys");
    }

    public HmacJwt() {
        this(getDefaultHmacDir());
    }

    public HmacJwt(Path secretDir) {
        this(KeyMinterConfigHolder.get(), secretDir);
    }

    public HmacJwt(KeyMinterProperties properties, Path secretDir) {
        super(properties);
        if (secretDir == null) {
            secretDir = getDefaultHmacDir();
        } else {
            secretDir = secretDir.normalize();
            validateDirectoryPath(secretDir);
            if (!secretDir.getFileName().toString().equals("hmac-keys")) {
                secretDir = secretDir.resolve("hmac-keys");
            }
        }
        this.currentKeyPath = secretDir;
        if (isKeyRotationEnabled()) {    // 读配置
            enableKeyRotation();
        }
        initializeKeyVersions();
        if (activeKeyId == null) log.warn("No keys found in directory: {}", secretDir);
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return generateHmacKey(algorithm, null);
    }

    @Override
    public boolean generateHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        String newKeyId = generateKeyVersionId(algorithm);
        return rotateHmacKey(algorithm, newKeyId, length);
    }

    @Override
    public boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
        validateHmacAlgorithm(algorithm);
        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }
        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier,
                    currentKeyPath,
                    () -> {
                        int keyLength = length == null ? getKeyLengthForAlgorithm(algorithm) : length;
                        keyLength = Math.max(keyLength, MIN_HMAC_KEY_LENGTH);
                        return generateSecureSecret(keyLength);
                    },
                    (secret, tempDir) -> {
                        // 保存密钥文件
                        Path secretFile = tempDir.resolve("secret.key");
                        // 使用安全方式写入
                        secret.useBytes(bytes -> {
                            try {
                                Files.write(secretFile, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                                setRestrictiveFilePermissions(secretFile);
                                return null;
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                        // 保存算法信息
                        Path algorithmFile = tempDir.resolve("algorithm.info");
                        Files.writeString(algorithmFile, algorithm.name());
                    },
                    (secret) -> {
                        KeyVersion newVersion = new KeyVersion(newKeyIdentifier, algorithm,
                                currentKeyPath.resolve(newKeyIdentifier).toString());
                        newVersion.setCreatedTime(LocalDateTime.now());

                        versionSecrets.put(newKeyIdentifier, secret);
                        keyVersions.put(newKeyIdentifier, newVersion);
                        log.info("HMAC key rotated successfully. New key ID: {}, algorithm: {}", newKeyIdentifier, algorithm);
                    }
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public HmacJwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    @Override
    public HmacJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        JwtAlgo autoed = autoLoadKey(preferredKeyId);
        if (autoed != null) return (HmacJwt) autoed;
        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!force && !hasKeyFilesInDirectory(tag)) {
            log.warn("No {} HMAC key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            this.activeKeyId = null;
            this.currentSecret = null;
            return this;
        }
        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
    }

    @Override
    public void loadExistingKeyVersions() {
        try {
            if (Files.exists(currentKeyPath) && Files.isDirectory(currentKeyPath)) {
                try (var paths = Files.list(currentKeyPath)) {
                    paths.filter(Files::isDirectory)
                            .filter(this::isKeyVersionDir)
                            .forEach(this::loadKeyVersion);
                }
                if (versionSecrets.isEmpty()) loadLegacyKeys();
            }
        } catch (IOException e) {
            log.error("Failed to load existing key versions: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasSecret = Files.exists(dir.resolve("secret.key"));
        boolean hasAlg = Files.exists(dir.resolve("algorithm.info"));
        boolean likeHmac = name.contains("hmac") && name.contains("-v");
        return hasSecret || hasAlg || likeHmac;
    }

    @Override
    protected void loadKeyVersion(Path versionDir) {
        try {
            String keyId = versionDir.getFileName().toString();
            boolean isActive = Files.exists(versionDir.resolve(".active"));

            // 使用安全方式加载密钥
            SecureByteArray secret = loadSecureSecretFromDir(versionDir);
            if (secret != null && secret.length() > 0) {
                versionSecrets.put(keyId, secret);

                Algorithm algorithm = getAlgorithmFromDir(versionDir);
                KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
                version.setActive(isActive);
                version.setCreatedTime(getCreationTimeFromDir(versionDir));

                if (isActive) {
                    version.setActivatedTime(LocalDateTime.now());
                    // 清理旧的当前密钥
                    if (this.currentSecret != null && !this.currentSecret.equals(secret)) {
                        this.currentSecret.wipe();
                    }
                    this.currentSecret = secret;
                    this.activeKeyId = keyId;
                }

                keyVersions.put(keyId, version);
                log.debug("Loaded HMAC key version: {}, active: {}, algorithm: {}",
                        keyId, isActive, algorithm);
            }
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        }
    }

    @Override
    public void loadKeyPair(String keyId) {
        SecureByteArray secret = versionSecrets.get(keyId);
        if (secret == null || secret.isWiped()) {
            try {
                Path versionDir = currentKeyPath.resolve(keyId);
                secret = loadSecureSecretFromDir(versionDir);
                if (secret == null || secret.length() == 0) {
                    throw new IllegalArgumentException("Secret not found for version: " + keyId);
                }
                versionSecrets.put(keyId, secret);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to load secret for version: " + keyId, e);
            }
        }
        if (this.currentSecret != null && !this.currentSecret.equals(secret) && !this.currentSecret.isWiped()) {
            this.currentSecret.wipe();
        }
        this.currentSecret = secret;
        this.activeKeyId = keyId;
        markKeyActive(keyId);
    }

    @Override
    public boolean verifyWithKeyVersion(String keyId, String token) {
        try {
            SecureByteArray secret = versionSecrets.get(keyId);
            if (secret == null) {
                secret = loadSecureSecretFromDir(currentKeyPath.resolve(keyId));
                if (secret != null && secret.length() > 0) {
                    versionSecrets.put(keyId, secret);
                }
            }
            if (secret != null) {
                // 安全地使用密钥 - 防止内存残留
                return Boolean.TRUE.equals(secret.useBytes(bytes -> {
                    try {
                        SecretKey key = Keys.hmacShaKeyFor(bytes);
                        Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
                        return true;
                    } catch (Exception e) {
                        log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
                        return false;
                    }
                }));
            }
        } catch (Exception e) {
            log.error("Token verification failed with key {}: {}", keyId, e.getMessage());
        }
        return false;
    }

    @Override
    public Object getCurrentKey() {
        return currentSecret;
    }

    @Override
    public Object getKeyByVersion(String keyId) {
        return versionSecrets.get(keyId);
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateHmacAlgorithm(algorithm);
        if (currentSecret == null) {
            throw new IllegalStateException("No active HMAC key. Call setActiveKey or rotateKey first.");
        }
        // 安全地使用密钥生成JWT
        return currentSecret.useBytes(bytes -> {
            SecretKey key = Keys.hmacShaKeyFor(bytes);
            JwtBuilder builder = createJwtBuilder(properties, customClaims);
            return builder.signWith(key, getSignAlgorithm(algorithm)).compact();
        });
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            if (currentSecret != null) {
                // 安全地使用密钥验证
                return Boolean.TRUE.equals(currentSecret.useBytes(bytes -> {
                    try {
                        SecretKey key = Keys.hmacShaKeyFor(bytes);
                        Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
                        return true;
                    } catch (JwtException | IllegalArgumentException e) {
                        return false;
                    }
                }));
            }
        } catch (Exception e) {
            log.error("Token verification error: {}", e.getMessage());
        }
        return false;
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        if (currentSecret != null) {
            // 安全地使用密钥解析
            return currentSecret.useBytes(bytes -> {
                try {
                    SecretKey key = Keys.hmacShaKeyFor(bytes);
                    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
                } catch (JwtException e) {
                    throw new SecurityException("HMAC JWT validation failed", e);
                }
            });
        }
        throw new SecurityException("HMAC JWT validation failed - no active key");
    }

    @Override
    public String generateJwt(JwtProperties properties, Algorithm algorithmType) {
        return generateJwt(properties, null, algorithmType);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        validateHmacAlgorithm(algorithm);
        return switch (algorithm) {
            case HMAC256 -> Jwts.SIG.HS256;
            case HMAC384 -> Jwts.SIG.HS384;
            case HMAC512 -> Jwts.SIG.HS512;
            default -> throw new IllegalStateException("Unsupported HMAC algorithm: " + algorithm);
        };
    }

    @Override
    public String getKeyInfo() {
        return String.format("HMAC Keys - Active: %s, Total versions: %d, Key rotation: %s",
                activeKeyId, versionSecrets.size(), keyRotationEnabled ? "enabled" : "disabled");
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Algorithm algorithm : Algorithm.getHmacAlgorithms()) {
            String keyId = generateKeyVersionId(algorithm);
            boolean success = rotateHmacKey(algorithm, keyId, null);
            if (!success) allSuccess = false;
        }
        return allSuccess;
    }

    @Override
    public String getAlgorithmInfo() {
        return "HMAC algorithms: HS256, HS384, HS512 with key rotation support";
    }

    @Override
    public void close() {
        cleanupSecrets();
    }

    protected void cleanupSecrets() {
        // 清理所有版本密钥
        versionSecrets.values().forEach(SecureByteArray::wipe);
        versionSecrets.clear();

        // 清理当前密钥
        if (currentSecret != null) {
            currentSecret.wipe();
            currentSecret = null;
        }
        // 清理父类资源
        keyVersions.clear();
        activeKeyId = null;
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag, null).isPresent();
    }

    @Override
    protected void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag, null).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}",
                        tag == null ? "" : " " + tag, currentKeyPath));
    }


    private int getKeyLengthForAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case HMAC256 -> 64;
            case HMAC384 -> 96;
            case HMAC512 -> 128;
            default -> DEFAULT_HMAC_KEY_LENGTH;
        };
    }

    // 原子性生成安全密钥
    private SecureByteArray generateSecureSecret(int length) {
        // 使用安全的随机数生成器，每次重新获取
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        // 转换为安全字节数组
        SecureByteArray secret = SecureByteArray.fromBytes(randomBytes);
        // 清理临时数组
        Arrays.fill(randomBytes, (byte) 0);
        return secret;
    }

    @Override
    protected void setRestrictiveFilePermissions(Path path) {
        super.setRestrictiveFilePermissions(path);
    }

    // 新增：安全地从目录加载密钥
    private SecureByteArray loadSecureSecretFromDir(Path versionDir) throws IOException {
        Path secretFile = versionDir.resolve("secret.key");
        if (!Files.exists(secretFile)) {
            return null;
        }
        // 原子性读取文件
        byte[] fileBytes = Files.readAllBytes(secretFile);
        try {
            return SecureByteArray.fromBytes(fileBytes);
        } finally {
            // 清理临时数组
            Arrays.fill(fileBytes, (byte) 0);
        }
    }

    private Algorithm getAlgorithmFromDir(Path versionDir) throws IOException {
        Path algorithmFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algorithmFile)) {
            String algorithmStr = Files.readString(algorithmFile, StandardCharsets.UTF_8).trim();
            try {
                return Algorithm.valueOf(algorithmStr);
            } catch (IllegalArgumentException ignored) {
                log.warn("Unknown algorithm: {}, defaulting to HMAC256", algorithmStr);
            }
        }
        return Algorithm.HMAC256;
    }

    private void loadLegacyKeys() {
        try (Stream<Path> paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isRegularFile)
                    .filter(file -> file.getFileName().toString().endsWith(".key"))
                    .filter(file -> !file.getFileName().toString().startsWith("."))
                    .forEach(this::migrateLegacyKey);
        } catch (IOException e) {
            log.debug("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    private void migrateLegacyKey(Path legacyPath) {
        try {
            byte[] fileBytes = Files.readAllBytes(legacyPath);
            if (fileBytes.length == 0) {
                return;
            }

            SecureByteArray secret = SecureByteArray.fromBytes(fileBytes);
            if (secret.length() == 0) {
                secret.wipe();
                return;
            }

            // 使用更安全的keyId生成
            String keyId = KEY_VERSION_PREFIX + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-" +
                    UUID.randomUUID().toString().substring(0, 12) + "-legacy"; // 增加随机位数

            migrateToVersioned(keyId, secret);
        } catch (Exception e) {
            log.warn("Failed to migrate legacy key {}: {}", legacyPath, e.getMessage());
        }
    }

    private void migrateToVersioned(String keyId, SecureByteArray secret) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);

        // 安全地写入密钥文件
        writeSecretToFileAtomically(versionDir.resolve("secret.key"), secret);

        // 写入算法信息
        Path algorithmFile = versionDir.resolve("algorithm.info");
        Files.writeString(algorithmFile, Algorithm.HMAC256.name(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 创建活跃标记
        Files.createFile(versionDir.resolve(".active"));

        // 更新内存映射
        versionSecrets.put(keyId, secret);

        KeyVersion version = new KeyVersion(keyId, Algorithm.HMAC256, versionDir.toString());
        version.setActive(true);
        version.setCreatedTime(LocalDateTime.now());
        version.setActivatedTime(LocalDateTime.now());

        keyVersions.put(keyId, version);
        this.activeKeyId = keyId;
        this.currentSecret = secret;

        log.info("Migrated legacy HMAC key to versioned format: {}", keyId);
    }

    // 新增：原子性写入密钥文件
    private void writeSecretToFileAtomically(Path targetFile, SecureByteArray secret) throws IOException {
        Path tempFile = targetFile.getParent().resolve(targetFile.getFileName() + ".tmp");

        try {
            // 使用安全方式写入临时文件
            secret.useBytes(bytes -> {
                try {
                    Files.write(tempFile, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return null;
            });
            // 原子性移动
            Files.move(tempFile, targetFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            // 设置文件权限
            setRestrictiveFilePermissions(targetFile);

        } finally {
            // 清理临时文件
            Files.deleteIfExists(tempFile);
        }
    }
}


