package keyMinter.internal.core.support;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import keyMinter.config.KeyMinterProperties;
import keyMinter.internal.core.JwtAlgo;
import keyMinter.model.Algorithm;
import keyMinter.model.JwtProperties;
import keyMinter.model.KeyVersion;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
@Slf4j
abstract class AbstractJwtAlgo implements JwtAlgo {
    protected final Map<String, Long> revokedFingerprints = new ConcurrentHashMap<>();
    protected Instant DEFAULT_NEW_EXP_MS = Instant.now().plus(Duration.ofMinutes(30));
    protected final Map<String, KeyVersion> keyVersions = new ConcurrentHashMap<>();
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final ReentrantLock activeKeyLock = new ReentrantLock();
    protected final KeyMinterProperties keyMinterProperties;
    protected static final int DEFAULT_RSA_KEY_SIZE = 2048;
    protected static final int DEFAULT_HMAC_KEY_LENGTH = 64;
    protected static final int MIN_HMAC_KEY_LENGTH = 32;
    protected long REFRESH_GRACE_MS = 5 * 60 * 1000L;
    protected boolean keyRotationEnabled = false;
    protected String activeKeyId;
    protected Path currentKeyPath;

    public AbstractJwtAlgo(KeyMinterProperties keyMinterProperties) {
        this.keyMinterProperties = keyMinterProperties;
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateJwtProperties(properties);
        validateAlgorithm(algorithm);
        dispatchAlgorithmValidation(algorithm);
        return generateJwt(properties, customClaims, algorithm);
    }

    @Override
    public String generateToken(JwtProperties properties, Algorithm algorithm) {
        validateJwtProperties(properties);
        validateAlgorithm(algorithm);
        dispatchAlgorithmValidation(algorithm);
        return generateJwt(properties, algorithm);
    }
//    public abstract Claims decodePayload(String token);

    @Override
    public boolean manageSecret(String secret) {
        log.warn("Secret management not implemented");
        return false;
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        if (!isKeyRotationEnabled()) {
            throw new UnsupportedOperationException("Key rotation is not enabled");
        }
        log.warn("Key rotation not implemented for this algorithm");
        return false;
    }

    @Override
    public List<String> getKeyVersions() {
        return new ArrayList<>(keyVersions.keySet());
    }

    @Override
    public List<String> getKeyVersions(Algorithm algorithm) {
        if (keyVersions.isEmpty()) {
            return Collections.emptyList();
        } else {
            return keyVersions.values().stream().filter(
                            v -> v.getAlgorithm() == algorithm)
                    .map(KeyVersion::getKeyId).collect(Collectors.toList());
        }
    }

    @Override
    public boolean setActiveKey(String keyId) {
        activeKeyLock.lock();
        try {
            if (!keyVersions.containsKey(keyId)) {
                log.error("Key version not found: {}", keyId);
                return false;
            }
            if (activeKeyId != null) {
                KeyVersion oldActive = keyVersions.get(activeKeyId);
                oldActive.setActive(false);
                oldActive.setExpiredTime(LocalDateTime.now().plusDays(7));
            }
            KeyVersion newActive = keyVersions.get(keyId);
            newActive.setActive(true);
            newActive.setActivatedTime(LocalDateTime.now());
            activeKeyId = keyId;
            loadKeyPair(keyId);
            return true;
        } finally {
            activeKeyLock.unlock();
        }
    }

    @Override
    public String getActiveKeyId() {
        return activeKeyId;
    }

    public String generateKeyVersionId(Algorithm algorithm) {
        return algorithm.name() + "-v" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-"
                + UUID.randomUUID().toString().substring(0, 8);
    }

    protected boolean isKeyRotationEnabled() {
        return keyMinterProperties.isEnableRotation();
    }

    protected void loadKeyPair(String keyId) {
        log.warn("loadKeyPair not implemented for key version: {}", keyId);
    }

    // 新增：验证目录路径安全性
    protected void validateDirectoryPath(Path path) {
        Path normalized = path.normalize();
        if (!normalized.equals(path)) {
            throw new SecurityException("Invalid directory path: " + path);
        }
        if (Files.isSymbolicLink(path)) {
            throw new SecurityException("Symbolic links are not allowed: " + path);
        }
    }

    protected void enableKeyRotation() {
        this.keyRotationEnabled = true;
    }

    protected void initializeKeyVersions() {
        if (currentKeyPath != null) {
            loadExistingKeyVersions();
        }
    }

    protected Optional<Path> findKeyDir(String tag, Predicate<Path> extraFilter) {
        if (!Files.exists(currentKeyPath)) return Optional.empty();
        Predicate<Path> filter = directoriesContainingTag(tag);
        if (extraFilter != null) {
            filter = filter.and(extraFilter);
        }

        try (Stream<Path> dirs = Files.list(currentKeyPath)) {
            return dirs.filter(filter)
                    .max(Comparator.comparing(this::getDirTimestamp));
        } catch (IOException e) {
            log.error("Failed to scan directory: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public abstract boolean verifyWithKeyVersion(String keyId, String token);

    public abstract String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm);

    public abstract String generateJwt(JwtProperties properties, Algorithm algorithm);

    protected void validateJwtProperties(JwtProperties properties) {
        if (properties == null) {
            throw new IllegalArgumentException("JwtProperties cannot be null");
        }
        if (StringUtils.isBlank(properties.getSubject())) {
            throw new IllegalArgumentException("JWT subject cannot be null or empty");
        }
        long remainSeconds = Duration.between(Instant.now(), properties.getExpiration()).toSeconds();
        if (properties.getExpiration() == null || remainSeconds <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        if (StringUtils.isBlank(properties.getIssuer())) {
            throw new IllegalArgumentException("JWT issuer cannot be null or empty");
        }
    }

    protected JwtBuilder createJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(toDate(properties.getExpiration()));
        if (customClaims != null && !customClaims.isEmpty()) {
            builder.claims(customClaims);
        }
        return builder;
    }

    public static Date toDate(Instant instant) {
        return Date.from(instant);
    }

    @Override
    public List<KeyVersion> listAllKeys(String directory) {
        if (directory == null) return Collections.emptyList();
        Path baseDir = Paths.get(directory);
        if (!Files.exists(baseDir) || !Files.isDirectory(baseDir)) return Collections.emptyList();
        List<KeyVersion> keys = new ArrayList<>();

        try (Stream<Path> typeDirs = Files.list(baseDir)) {
            typeDirs.filter(Files::isDirectory).forEach(typeDir -> {
                try (Stream<Path> versionDirs = Files.list(typeDir)) {
                    versionDirs.filter(Files::isDirectory).forEach(versionDir -> {
                        String keyId = versionDir.getFileName().toString();
                        // 读取算法
                        Algorithm algorithm = detectAlgorithmFromDir(typeDir.getFileName().toString(), versionDir);
                        // 是否活跃
                        boolean active = Files.exists(versionDir.resolve(".active"));
                        // 创建时间
                        LocalDateTime createdTime = parseCreationTimeFromDirName(keyId);
                        // 激活时间（如果活跃就取现在，否则为 null，可按需改为从文件读取）
                        LocalDateTime activatedTime = active ? LocalDateTime.now() : null;
                        // todo 过期时间
                        LocalDateTime expiredTime = null;
                        KeyVersion kv = KeyVersion.builder()
                                .keyId(keyId)
                                .algorithm(algorithm)
                                .createdTime(createdTime)
                                .activatedTime(activatedTime)
                                .expiredTime(expiredTime)
                                .active(active).keyPath(versionDir.toString())
                                .build();
                        keys.add(kv);
                    });
                } catch (IOException e) {
                    log.error("Error reading key directory: {}", e.getMessage());
                }
            });
        } catch (IOException e) {
            return Collections.emptyList();
        }
        return keys;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        if (customClaims == null) return null;
        if (customClaims instanceof Map) return (Map<String, Object>) customClaims;
        if (customClaims instanceof String) {
            try {
                return OBJECT_MAPPER.readValue((String) customClaims, new TypeReference<>() {
                });
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Invalid JSON claims string", e);
            }
        }
        try {
            String json = OBJECT_MAPPER.writeValueAsString(customClaims);
            return OBJECT_MAPPER.readValue(json, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to convert object to claims map", e);
        }
    }

    @Override
    public String getKeyInfo() {
        return "Key directory: " + (currentKeyPath != null ? currentKeyPath : "Not set") + ", Active key: " + activeKeyId + ", Key versions: " + keyVersions.size();
    }

    protected void markKeyActive(String keyId) {
        KeyVersion version = keyVersions.get(keyId);
        if (version == null) return;

        version.setActivatedTime(LocalDateTime.now());
        version.setActive(true);
        try {
            Path marker = currentKeyPath.resolve(keyId).resolve(".active");
            if (!Files.exists(marker)) Files.createFile(marker);
        } catch (IOException e) {
            log.warn("Failed to mark key active: {}", e.getMessage());
        }
    }

    @Override
    public Path getKeyPath() {
        return currentKeyPath;
    }

    @Override
    public String getAlgorithmInfo() {
        return "Default algorithm information";
    }

    @Override
    public boolean keyPairExists() {
        return !keyVersions.isEmpty();
    }

    @Override
    public boolean keyPairExists(Algorithm algorithm) {
        return keyVersions.values().stream().anyMatch(v -> v.getAlgorithm() == algorithm);
    }

    @Override
    public JwtAlgo autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        JwtAlgo autoed = autoLoadKey(preferredKeyId);
        if (autoed != null) return autoed;
        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!(force || hasKeyFilesInDirectory(tag))) {
            log.warn("No {} key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            this.activeKeyId = null;
            return this;
        }
        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
    }

    @Override
    public JwtAlgo autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    protected abstract boolean hasKeyFilesInDirectory(String tag);

    protected abstract void loadFirstKeyFromDirectory(String tag);

    public JwtAlgo withKeyDirectory(Path keyDir) {
        this.currentKeyPath = keyDir;
        initializeKeyVersions();
        return this;
    }

    protected void validateAlgorithm(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
    }

    protected JwtAlgo autoLoadKey(String preferredKeyId) {
        if (preferredKeyId != null && !preferredKeyId.trim().isEmpty()) {
            if (keyVersions.containsKey(preferredKeyId)) {
                setActiveKey(preferredKeyId);
                return this;
            }
            try {
                Path candidate = currentKeyPath.resolve(preferredKeyId);
                if (Files.exists(candidate) && Files.isDirectory(candidate)) {
                    loadKeyVersion(candidate);
                    if (keyVersions.containsKey(preferredKeyId)) {
                        setActiveKey(preferredKeyId);
                        return this;
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to load preferred key {} from disk: {}", preferredKeyId, e.getMessage());
            }
            log.warn("Specified key {} not found", preferredKeyId);
            return this; // 没找到，也不创建新的
        }
        return null;
    }

    protected abstract void loadKeyVersion(Path path);

    protected abstract boolean isKeyVersionDir(Path dir);

    protected void validateHmacAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isHmac()) {
            throw new IllegalArgumentException("Algorithm must be HMAC type: " + algorithm);
        }
    }

    protected LocalDateTime getCreationTimeFromDir(Path versionDir) {
        LocalDateTime meta = readVersionCreatedTime(versionDir);
        if (meta != null) return meta;
        try {
            String dirName = versionDir.getFileName().toString();
            if (dirName.contains("-v")) {
                String timestamp = dirName.substring(dirName.indexOf("-v") + 2, dirName.indexOf("-v") + 17);
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception ignored) {
        }
        return LocalDateTime.MIN;
    }

    protected Predicate<Path> directoriesContainingTag(String tag) {
        Predicate<Path> filter = Files::isDirectory;
        if (tag != null) {
            String upperTag = tag.toUpperCase(Locale.ROOT);
            filter = filter.and(dir -> dir.getFileName().toString()
                    .toUpperCase(Locale.ROOT).contains(upperTag));
        }
        return filter;
    }

    protected void validateRsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isRsa()) {
            throw new IllegalArgumentException("Algorithm must be RSA type: " + algorithm);
        }
    }

    protected void validateEcdsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isEcdsa()) {
            throw new IllegalArgumentException("Algorithm must be ECDSA type: " + algorithm);
        }
    }

    protected void validateEddsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isEddsa()) {
            throw new IllegalArgumentException("Algorithm must be EdDSA type: " + algorithm);
        }
    }

    protected abstract Object getSignAlgorithm(Algorithm algorithm);

    protected void setRestrictiveFilePermissions(Path path) {
        try {
            java.nio.file.FileSystem fs = java.nio.file.FileSystems.getDefault();
            boolean posix = fs.supportedFileAttributeViews().contains("posix");
            if (posix) {
                Files.setPosixFilePermissions(path, EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ, java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            } else {
                java.nio.file.attribute.AclFileAttributeView aclView = Files.getFileAttributeView(path, java.nio.file.attribute.AclFileAttributeView.class);
                if (aclView != null) {
                    java.nio.file.attribute.UserPrincipal owner = Files.getOwner(path);
                    java.nio.file.attribute.AclEntry entry = java.nio.file.attribute.AclEntry.newBuilder()
                            .setType(java.nio.file.attribute.AclEntryType.ALLOW)
                            .setPrincipal(owner)
                            .setPermissions(java.nio.file.attribute.AclEntryPermission.READ_DATA, java.nio.file.attribute.AclEntryPermission.WRITE_DATA,
                                    java.nio.file.attribute.AclEntryPermission.READ_ATTRIBUTES, java.nio.file.attribute.AclEntryPermission.WRITE_ATTRIBUTES,
                                    java.nio.file.attribute.AclEntryPermission.EXECUTE, java.nio.file.attribute.AclEntryPermission.DELETE,
                                    java.nio.file.attribute.AclEntryPermission.DELETE_CHILD, java.nio.file.attribute.AclEntryPermission.SYNCHRONIZE)
                            .build();
                    aclView.setAcl(java.util.List.of(entry));
                } else {
                    Files.setAttribute(path, "dos:hidden", true);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to set restrictive permissions for {}: {}", path, e.getMessage());
        }
    }

    private Algorithm detectAlgorithmFromDir(String typeDirName, Path versionDir) {
        Path algFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algFile)) {
            try {
                return Algorithm.valueOf(Files.readString(algFile, StandardCharsets.UTF_8).trim());
            } catch (Exception ignored) {
            }
        }
        // 默认根据目录名推测
        return switch (typeDirName.toLowerCase()) {
            case "hmac-keys" -> Algorithm.HMAC256;
            case "rsa-keys" -> Algorithm.RSA256;
            case "ec-keys" -> Algorithm.ES256;
            case "eddsa-keys" -> Algorithm.Ed25519;
            default -> throw new IllegalStateException("Unexpected value: " + typeDirName.toLowerCase());
        };
    }

    // 从 keyId 解析创建时间，例如 HMAC256-v20251201-225826-dcaa51c9
    private LocalDateTime parseCreationTimeFromDirName(String keyId) {
        try {
            int idx = keyId.indexOf("-v");
            if (idx != -1 && keyId.length() >= idx + 16) {
                String timestamp = keyId.substring(idx + 2, idx + 16); // 20251201-225826
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception ignored) {
        }
        return LocalDateTime.now().minusDays(1);
    }

    @Override
    public LocalDateTime getDirTimestamp(Path dir) {
        LocalDateTime meta = readVersionCreatedTime(dir);
        if (meta != null) return meta;
        String dirName = dir.getFileName().toString();
        try {
            int start = dirName.indexOf("-v");
            if (start != -1 && dirName.length() >= start + 17) {
                String timestamp = dirName.substring(start + 2, start + 17);
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception ignored) {
        }
        return LocalDateTime.MIN;
    }

    private LocalDateTime readVersionCreatedTime(Path dir) {
        try {
            Path meta = dir.resolve("version.json");
            if (!Files.exists(meta)) return null;
            String s = Files.readString(meta).trim();
            int idx = s.indexOf("\"createdTime\":\"");
            if (idx >= 0) {
                int start = idx + "\"createdTime\":\"".length();
                int end = s.indexOf("\"", start);
                if (end > start) {
                    String iso = s.substring(start, end);
                    return LocalDateTime.parse(iso);
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void dispatchAlgorithmValidation(Algorithm algorithm) {
        if (algorithm.isHmac()) {
            validateHmacAlgorithm(algorithm);
        } else if (algorithm.isRsa()) {
            validateRsaAlgorithm(algorithm);
        } else if (algorithm.isEcdsa()) {
            validateEcdsaAlgorithm(algorithm);
        } else if (algorithm.isEddsa()) {
            validateEddsaAlgorithm(algorithm);
        }
    }
}
