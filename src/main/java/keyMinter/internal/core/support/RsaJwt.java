package keyMinter.internal.core.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.micrometer.common.util.StringUtils;
import keyMinter.config.KeyMinterConfigHolder;
import keyMinter.config.KeyMinterProperties;
import keyMinter.internal.rotation.KeyRotation;
import keyMinter.model.Algorithm;
import keyMinter.model.JwtProperties;
import keyMinter.model.KeyVersion;
import keyMinter.spi.SecretDirProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Getter
public class RsaJwt extends AbstractJwtAlgo {
    private static Path getDefaultRsaDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("rsa-keys");
    }

    private final Map<String, KeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private static final String DEFAULT_PRIVATE_KEY_FILENAME = "private.key";
    private static final String DEFAULT_PUBLIC_KEY_FILENAME = "public.key";
    private Path currentPrivateKeyPath;
    private Path currentPublicKeyPath;
    private KeyPair keyPair;

    public RsaJwt() {
        this(getDefaultRsaDir());
    }

    public RsaJwt(Path path) {
        this(KeyMinterConfigHolder.get(), path);
    }

    public RsaJwt(KeyMinterProperties properties, Path directory) {
        super(properties);
        if (directory == null) {
            directory = getDefaultRsaDir();
        } else {
            directory = directory.normalize();
            validateDirectoryPath(directory);
            if (!directory.getFileName().toString().equals("rsa-keys")) {
                directory = directory.resolve("rsa-keys");
            }
        }
        this.currentKeyPath = directory;
        if (isKeyRotationEnabled()) {
            enableKeyRotation();
        }
        initializeKeyVersions();
        if (activeKeyId == null) {
            log.warn("No keys found in directory: {}", directory);
        }
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag, dir -> Files.exists(dir.resolve("private.key")) && Files.exists(dir.resolve("public.key"))).isPresent();
    }

    @Override
    protected void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag, dir -> Files.exists(dir.resolve("private.key")) && Files.exists(dir.resolve("public.key")))
                .ifPresentOrElse(
                        dir -> setActiveKey(dir.getFileName().toString()),
                        () -> log.error("No{} key directory found under {}",
                                tag == null ? "" : " " + tag, currentKeyPath));
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
                if (keyVersions.isEmpty()) {
                    loadLegacyKeyPair();
                }
            }
        } catch (IOException e) {
            log.error("Failed to load existing RSA key versions: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasPrivate = Files.exists(dir.resolve("private.key"));
        boolean hasPublic = Files.exists(dir.resolve("public.key"));
        boolean hasAlg = Files.exists(dir.resolve("algorithm.info"));
        boolean likeRSA = name.contains("rsa") && name.contains("-v");   // 目录名兜底
        return (hasPrivate && hasPublic) || hasAlg || likeRSA;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        validateRsaAlgorithm(algorithm);
        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }
        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier,
                    currentKeyPath,
                    () -> {
                        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                        int keySize = algorithm == Algorithm.RSA384 ? 3072 :
                                algorithm == Algorithm.RSA512 ? 4096 : DEFAULT_RSA_KEY_SIZE;
                        keyPairGenerator.initialize(keySize);
                        return keyPairGenerator.generateKeyPair();
                    },
                    (keyPair, tempDir) -> {
                        // 保存私钥
                        Path privateKeyPath = tempDir.resolve("private.key");
                        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded(),
                                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                        // 保存公钥
                        Path publicKeyPath = tempDir.resolve("public.key");
                        Files.write(publicKeyPath, keyPair.getPublic().getEncoded(),
                                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                        // 保存算法信息
                        Path algorithmFile = tempDir.resolve("algorithm.info");
                        Files.writeString(algorithmFile, algorithm.name());
                        // 设置文件权限
                        setRestrictiveFilePermissions(privateKeyPath);
                    },
                    (keyPair) -> {
                        KeyVersion newVersion = new KeyVersion(newKeyIdentifier, algorithm,
                                currentKeyPath.resolve(newKeyIdentifier).toString());
                        newVersion.setCreatedTime(LocalDateTime.now());

                        versionKeyPairs.put(newKeyIdentifier, keyPair);
                        keyVersions.put(newKeyIdentifier, newVersion);

                        log.info("RSA key rotated successfully. New key ID: {}, algorithm: {}", newKeyIdentifier, algorithm);
                    }
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void loadKeyPair(String keyId) {
        if (!versionKeyPairs.containsKey(keyId)) {
            try {
                KeyPair kp = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (kp != null) versionKeyPairs.put(keyId, kp);
                else throw new IllegalArgumentException("Key pair not found: " + keyId);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to load key pair: " + keyId, e);
            }
        }
        this.keyPair = versionKeyPairs.get(keyId);
        this.activeKeyId = keyId;
        markKeyActive(keyId);
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            if (keyPair != null) {
                Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Token verification failed with active key: {}", e.getMessage());
        }
        return false;
    }

    @Override
    public boolean verifyWithKeyVersion(String keyId, String token) {
        try {
            KeyPair historicalKeyPair = versionKeyPairs.get(keyId);
            if (historicalKeyPair == null) {
                // 尝试加载
                historicalKeyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (historicalKeyPair != null) {
                    versionKeyPairs.put(keyId, historicalKeyPair);
                }
            }
            if (historicalKeyPair != null) {
                Jwts.parser().verifyWith(historicalKeyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            }
        } catch (Exception e) {
            log.error("Token verification failed with key {}: {}", keyId, e.getMessage());
        }
        return false;
    }

    @Override
    public Object getCurrentKey() {
        return keyPair;
    }

    @Override
    public Object getKeyByVersion(String keyId) {
        return versionKeyPairs.get(keyId);
    }

    @Override
    public void close() {
        cleanup();
    }

    protected void cleanup() {
        // 清理所有版本密钥
        versionKeyPairs.clear();
        // 清理当前密钥
        keyPair = null; // 对于 RsaJwt
        // 清理父类资源
        keyVersions.clear();
        activeKeyId = null;
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateRsaAlgorithm(algorithm);
        if (keyPair == null) {
            throw new IllegalStateException("No active RSA key pair. Call setActiveKey or rotateKey first.");
        }
        return generateRsaJwt(properties, customClaims, algorithm);
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) throw new IllegalArgumentException("Token cannot be null or empty");
        if (keyPair != null) {
            try {
                return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                log.error("Failed to decode with active key: {}", e.getMessage());
            }
        }
        throw new SecurityException("RSA JWT validation failed with all available keys");
    }

    @Override
    public String generateJwt(JwtProperties properties, Algorithm algorithm) {
        return generateJwt(properties, null, algorithm);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("RSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    @Override
    public String getKeyInfo() {
        return String.format("RSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                activeKeyId, keyVersions.size(), keyRotationEnabled ? "enabled" : "disabled");
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Algorithm algorithm : Algorithm.getRsaAlgorithms()) {
            String keyId = generateKeyVersionId(algorithm);
            boolean success = rotateKey(algorithm, keyId);
            if (!success) {
                allSuccess = false;
                log.warn("Failed to generate key pair for: {}", algorithm);
            }
        }
        return allSuccess;
    }

    @Override
    public String getAlgorithmInfo() {
        return "RSA algorithms: RS256, RS384, RS512 with key rotation support";
    }


    protected void loadKeyVersion(Path versionDir) {
        try {
            String keyId = versionDir.getFileName().toString();
            // 检查是否活跃
            boolean isActive = Files.exists(versionDir.resolve(".active"));
            // 加载密钥对
            KeyPair keyPair = loadKeyPairFromDir(versionDir);
            if (keyPair != null) {
                versionKeyPairs.put(keyId, keyPair);
                KeyVersion version = new KeyVersion(keyId, Algorithm.RSA256, versionDir.toString());
                version.setActive(isActive);
                version.setCreatedTime(getCreationTimeFromDir(versionDir));
                if (isActive) version.setActivatedTime(LocalDateTime.now());

                keyVersions.put(keyId, version);
                if (isActive) {
                    this.activeKeyId = keyId;
                    this.keyPair = keyPair;
                }
                log.info("Loaded RSA key version: {}, active: {}", keyId, isActive);
            }
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        }
    }

    private KeyPair loadKeyPairFromDir(Path versionDir) throws Exception {
        Path privateKeyPath = versionDir.resolve("private.key");
        Path publicKeyPath = versionDir.resolve("public.key");
        return loadKeyPairFromPaths(privateKeyPath, publicKeyPath);
    }

    // 加载传统密钥对
    private void loadLegacyKeyPair() {
        this.currentPrivateKeyPath = currentKeyPath.resolve(DEFAULT_PRIVATE_KEY_FILENAME);
        this.currentPublicKeyPath = currentKeyPath.resolve(DEFAULT_PUBLIC_KEY_FILENAME);
        try {
            KeyPair keyPair = loadKeyPairFromPaths(currentPrivateKeyPath, currentPublicKeyPath);
            if (keyPair != null) {
                this.keyPair = keyPair;
                // 创建传统版本
                String legacyKeyId = "RSA256-v" + LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-" +
                        UUID.randomUUID().toString().substring(0, 8);

                KeyVersion version = new KeyVersion(
                        legacyKeyId,
                        Algorithm.RSA256,
                        currentPrivateKeyPath.getParent().toString()
                );
                version.setActive(true);
                version.setCreatedTime(LocalDateTime.now().minusDays(1));
                version.setActivatedTime(LocalDateTime.now());

                versionKeyPairs.put(legacyKeyId, keyPair);
                keyVersions.put(legacyKeyId, version);
                this.activeKeyId = legacyKeyId;
                log.info("Loaded legacy RSA key pair from: {}", currentPrivateKeyPath.getParent());
            } else {
                log.info("No legacy RSA key pair found at: {}. Call generateKeyPair to create one.", currentPrivateKeyPath.getParent());
            }
        } catch (Exception e) {
            log.warn("Failed to load legacy RSA key pair: {}", e.getMessage());
        }
    }

    private String generateRsaJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm
            algorithm) {
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder.signWith(keyPair.getPrivate(), getRsaSignAlgorithm(algorithm)).compact();
    }

    @Override
    protected void setRestrictiveFilePermissions(Path path) {
        super.setRestrictiveFilePermissions(path);
    }

    private SignatureAlgorithm getRsaSignAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case RSA256 -> Jwts.SIG.RS256;
            case RSA384 -> Jwts.SIG.RS384;
            case RSA512 -> Jwts.SIG.RS512;
            default -> throw new IllegalStateException("Unsupported RSA algorithm: " + algorithm);
        };
    }

    // 辅助方法
    private KeyPair loadKeyPairFromPaths(Path privateKeyPath, Path publicKeyPath) throws Exception {
        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        try {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
            try {
                PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                return new KeyPair(publicKey, privateKey);
            } finally {
                Arrays.fill(publicKeyBytes, (byte) 0);
            }
        } finally {
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }
}