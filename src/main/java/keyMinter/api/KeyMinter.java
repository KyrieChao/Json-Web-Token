package keyMinter.api;

import keyMinter.internal.core.JwtAlgo;
import keyMinter.internal.core.JwtFactory;
import keyMinter.model.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * JWT工具类
 * 提供简化的JWT操作接口
 */
@Slf4j
@Component
public class KeyMinter {

    private final JwtFactory factory;
    private volatile JwtAlgo algoInstance;
    private volatile Algorithm currentAlgorithm = DEFAULT_ALGORITHM;
    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.HMAC256;
    // 平滑过渡：保留上一个算法实例
    private volatile JwtAlgo previousAlgoInstance;
    private volatile long previousAlgoExpiryTime;
    private static final int DEFAULT_SECRET_LENGTH = 64;
    private static final long GRACE_PERIOD_MS = 3600_000; // 1小时宽限期
    private final AtomicLong gracefulUsageCount = new AtomicLong(0);
    private final AtomicLong blacklistHitCount = new AtomicLong(0);

    public KeyMinter(JwtFactory factory) {
        this.factory = factory;
        this.algoInstance = factory.get(DEFAULT_ALGORITHM);
    }

    /**
     * 切换默认算法
     *
     * @param algorithm 算法类型
     */
    public synchronized boolean switchTo(Algorithm algorithm) {
        return switchTo(algorithm, (String) null);
    }

    /**
     * 切换算法（字符串目录）并设置是否启用轮换
     *
     * @param algorithm 算法类型
     * @param directory 目录（字符串）
     */
    public synchronized boolean switchTo(Algorithm algorithm, String directory) {
        JwtAlgo newAlgo;
        try {
            newAlgo = factory.get(algorithm, directory);
            if (!newAlgo.keyPairExists()) return false;
        } catch (Exception e) {
            return false;
        }
        JwtAlgo oldAlgo = this.algoInstance;
        this.algoInstance = newAlgo;
        this.currentAlgorithm = algorithm;
        if (oldAlgo != null) {
            this.previousAlgoInstance = oldAlgo;
            this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
        }
        return true;
    }

    /**
     * 切换算法（路径目录）并设置是否启用轮换
     *
     * @param algorithm 算法类型
     * @param path      目录路径
     */
    public synchronized boolean switchTo(Algorithm algorithm, Path path) {
        JwtAlgo newAlgo;
        try {
            newAlgo = factory.get(algorithm, path);
            if (!newAlgo.keyPairExists()) return false;
        } catch (Exception e) {
            return false;
        }
        if (this.algoInstance != null) {
            this.previousAlgoInstance = this.algoInstance;
            this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
        }
        this.algoInstance = newAlgo;
        this.currentAlgorithm = algorithm;
        return true;
    }

    // --- Simplified AutoLoad API ---

    public JwtAlgo autoLoad(Algorithm algorithm) {
        return factory.autoLoad(algorithm);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return factory.autoLoad(algorithm, force);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return factory.autoLoad(algorithm, directory);
    }
    public JwtAlgo autoLoad(Algorithm algorithm, Path path) {
        return factory.autoLoad(algorithm, path);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return factory.autoLoad(algorithm, directory, keyId);
    }
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId,boolean  force) {
        return factory.autoLoad(algorithm, directory, keyId,force);
    }

    /**
     * 生成HMAC密钥
     *
     * @param algorithm HMAC算法
     * @param length    密钥长度
     * @return 是否生成成功
     */
    public boolean createHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        return algoInstance.generateHmacKey(
                Objects.requireNonNullElse(algorithm, DEFAULT_ALGORITHM),
                Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH)
        );
    }

    /**
     * 生成密钥对（非对称加密）
     *
     * @param algorithm 算法类型
     * @return 是否生成成功
     */
    public boolean createKeyPair(Algorithm algorithm) {
        validateAsymmetricAlgorithm(algorithm);
        return factory.get(algorithm).generateKeyPair(algorithm);
    }

    /**
     * 生成不包含自定义信息的Token（使用默认算法）
     *
     * @param jwtInfo JWT基本信息
     * @return 生成的Token字符串
     */
    public String generateToken(JwtProperties jwtInfo) {
        return generateToken(jwtInfo, currentAlgorithm);
    }

    public String generateToken(Algorithm algorithm, JwtProperties jwtInfo) {
        return generateToken(jwtInfo, algorithm);
    }

    /**
     * 生成不包含自定义信息的Token（指定算法）
     *
     * @param jwtInfo   JWT基本信息
     * @param algorithm 算法类型
     * @return 生成的Token字符串
     */
    public String generateToken(JwtProperties jwtInfo, Algorithm algorithm) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        return algoInstance.generateToken(properties, algorithm);
    }

    /**
     * 生成包含自定义信息的Token（泛型版本，使用默认算法）
     *
     * @param jwtInfo      JWT基本信息
     * @param customClaims 自定义声明对象
     * @param claimsType   自定义声明类型
     * @return 生成的Token字符串
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType) {
        return generateToken(jwtInfo, customClaims, claimsType, currentAlgorithm);
    }

    /**
     * 生成包含自定义信息的Token（泛型版本，指定算法）
     *
     * @param jwtInfo      JWT基本信息
     * @param customClaims 自定义声明对象
     * @param claimsType   自定义声明类型
     * @param algorithm    算法类型
     * @return 生成的Token字符串
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType, Algorithm algorithm) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        return algoInstance.generateToken(properties, algorithm, customClaims, claimsType);
    }

    /**
     * 获取Token的标准信息
     */
    public JwtStandardInfo getStandardInfo(String token) {
        return JwtDecoder.decodeStandardInfo(token, algoInstance);
    }

    /**
     * 解码Token为指定类型的对象
     */
    public <T> T decodeToObject(String token, Class<T> clazz) {
        return JwtDecoder.decodeToObject(token, clazz, algoInstance);
    }

    /**
     * 解码Token为完整Map
     */
    public Map<String, Object> decodeToFullMap(String token) {
        return JwtDecoder.decodeToFullMap(token, algoInstance);
    }

    /**
     * 获取Token的签发时间
     *
     * @param token JWT Token
     * @return 签发时间
     */
    public Date decodeIssuedAt(String token) {
        return JwtDecoder.decodeIssuedAt(token, algoInstance);
    }

    /**
     * 获取Token的过期时间
     */
    public Date decodeExpiration(String token) {
        return JwtDecoder.decodeExpiration(token, algoInstance);
    }

    /**
     * 获取Token的自定义信息
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 自定义声明对象
     */
    public <T> T getCustomClaims(String token, Class<T> clazz) {
        JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
        return fullInfo.getCustomClaims();
    }

    /**
     * 安全获取Token的自定义信息（不抛出异常）
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 自定义声明对象，解析失败时返回null
     */
    public <T> T getCustomClaimsSafe(String token, Class<T> clazz) {
        JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
        return fullInfo != null ? fullInfo.getCustomClaims() : null;
    }

    /**
     * 获取Token的完整信息
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 完整信息对象
     */
    public <T> JwtFullInfo<T> getFullInfo(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
    }

    /**
     * 安全获取Token的完整信息（不抛出异常）
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 完整信息对象，解析失败时返回null
     */
    public <T> JwtFullInfo<T> getFullInfoSafe(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
    }

    /**
     * 验证Token是否有效
     *
     * @param token JWT Token
     * @return 是否有效
     */
    public boolean verifyWithAlgorithm(String token, JwtAlgo algo) {
        return algo.verifyToken(token);
    }

    /**
     * 主验证：当前算法 → 宽限期算法（你的核心业务逻辑）
     */
    public boolean isValidToken(String token) {
        boolean valid = algoInstance.verifyToken(token);
        if (!valid) {
            JwtAlgo backup = getGracefulAlgo();
            if (backup != null) {
                gracefulUsageCount.incrementAndGet();
                return backup.verifyToken(token);
            }
        }
        return valid;
    }

    /**
     * 仅当前算法（严格模式，不换回旧算法）
     */
    public boolean isValidWithCurrent(String token) {
        return algoInstance.verifyToken(token);
    }

    /**
     * 仅宽限期算法（用于刷新场景，确认是旧Token才换发）
     */
    public boolean isValidWithGraceful(String token) {
        JwtAlgo backup = getGracefulAlgo();
        if (backup != null) return backup.verifyToken(token);
        return false;
    }

    /**
     * 获取JWT实例信息
     *
     * @return JWT实例描述信息
     */
    public String getJwtProperties() {
        return algoInstance.getKeyInfo();
    }

    /**
     * 获取算法信息
     *
     * @return 算法描述信息
     */
    public String getAlgorithmInfo() {
        return algoInstance.getAlgorithmInfo();
    }


    /**
     * 获取曲线信息（仅ECDSA算法）
     *
     * @return 曲线信息
     */
    public String getECDCurveInfo() {
        if (!algoInstance.isECD(currentAlgorithm)) {
            return null;
        }
        return algoInstance.getCurveInfo(currentAlgorithm);
    }

    public boolean verify(Algorithm algorithm, String token) {
        JwtAlgo algo = autoLoad(algorithm);
        return verifyWithAlgorithm(token, algo);
    }

    /**
     * 列出指定目录下的密钥
     *
     * @param directory 目录路径
     * @return 密钥列表
     */
    public List<KeyVersion> listAllKeys(String directory) {
        return algoInstance.listAllKeys(directory);
    }

    /**
     * 列出所有密钥
     *
     * @return 密钥列表
     */
    public List<KeyVersion> listAllKeys() {
        return algoInstance.listAllKeys();
    }


    /**
     * 列出指定目录下的密钥
     *
     * @param algorithm 算法类型
     * @param directory 目录路径
     * @return 密钥列表
     */
    public List<KeyVersion> listKeys(Algorithm algorithm, String directory) {
        return algoInstance.listKeys(algorithm, directory);
    }

    /**
     * 列出指定算法的密钥
     *
     * @return 密钥列表
     */
    public List<KeyVersion> listKeys() {
        return algoInstance.listKeys(currentAlgorithm);
    }

    /**
     * 获取指定算法的密钥版本列表
     */
    public List<String> getKeyVersions(Algorithm algorithm) {
        algorithm = algorithm == null ? currentAlgorithm : algorithm;
        return algoInstance.getKeyVersions(algorithm);
    }

    public List<String> getKeyVersions() {
        return algoInstance.getKeyVersions();
    }

    /**
     * 检查Token是否可解码
     *
     * @param token JWT Token
     * @return 是否可解码
     */
    public boolean isTokenDecodable(String token) {
        return JwtDecoder.isTokenDecodable(token, algoInstance);
    }


    /**
     * 构建JWT属性对象
     */
    private JwtProperties buildJwtProperties(JwtProperties jwtInfo) {
        if (jwtInfo == null) {
            throw new IllegalArgumentException("JwtProperties cannot be null");
        }
        return JwtProperties.builder()
                .subject(jwtInfo.getSubject())
                .issuer(jwtInfo.getIssuer())
                .expiration(jwtInfo.getExpiration()).build();
    }

    /**
     * 验证HMAC算法
     */
    private void validateHmacAlgorithm(Algorithm algorithm) {
        if (algorithm != null && !algorithm.isHmac()) {
            throw new IllegalArgumentException("Algorithm must be HMAC type: " + algorithm);
        }
    }

    /**
     * 验证非对称加密算法
     */
    private void validateAsymmetricAlgorithm(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        if (algorithm.isHmac()) {
            throw new IllegalArgumentException("HMAC algorithm does not support key pair generation: " + algorithm);
        }
    }

    /**
     * 拥有一把“最新版本”的密钥
     */
    public boolean generateAllKeyPairs() {
        return algoInstance.generateAllKeyPairs();
    }

    /**
     * 使用指定的密钥目录创建新的JwtAlgo实例
     *
     * @param keyDir 密钥目录路径
     * @return 新的JwtAlgo实例
     */
    public JwtAlgo withKeyDirectory(Path keyDir) {
        return algoInstance.withKeyDirectory(keyDir);
    }

    /**
     * 使用指定的密钥目录创建新的JwtAlgo实例
     *
     * @param keyDir 密钥目录路径字符串
     * @return 新的JwtAlgo实例
     */
    public JwtAlgo withKeyDirectory(String keyDir) {
        return algoInstance.withKeyDirectory(keyDir);
    }

    /**
     * 获取当前使用的密钥对象
     * 对于HMAC算法返回密钥字符串，对于非对称算法返回相应的密钥对对象
     *
     * @return 当前密钥对象
     */
    public Object getCurrentKey() {
        return algoInstance.getCurrentKey();
    }


    /**
     * 动态重新初始化
     */
    public void close() {
        algoInstance.close();
    }

    public JwtStandardInfo decodeStandardInfo(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeStandardInfo(token, load);
    }

    public <T> T decodeCustomInfo(Algorithm algorithm, String token, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeCustomClaimsSafe(token, load, clazz);
    }

    public boolean isDecodable(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.isTokenDecodable(token, load);
    }

    public String getKeyInfo(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, (String) null, keyId);
        return load.getKeyInfo();
    }

    public String getKeyVersions(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, (String) null, keyId);
        return load.getKeyVersions().toString();
    }

    public <T> String generateToken(Algorithm algorithm, String keyId, JwtProperties properties, T payload, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm, (String) null, keyId);
        return load.generateToken(properties, algorithm, payload, clazz);
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public void clearCache() {
        factory.clearCache();
    }

    public Object getKeyByVersion(String keyId) {
        return algoInstance.getKeyByVersion(keyId);
    }

    public boolean keyPairExists() {
        return algoInstance.keyPairExists();
    }

    public boolean keyPairExists(Algorithm algorithm) {
        return algoInstance.keyPairExists(algorithm);
    }

    public String getActiveKeyId() {
        return algoInstance.getActiveKeyId();
    }

    /**
     * 获取当前缓存大小
     */
    public int getCacheSize() {
        return factory.getCacheSize();
    }

    public Path getKeyPath() {
        return algoInstance.getKeyPath();
    }

    private void cleanupExpiredGracefulAlgo() {
        if (previousAlgoInstance != null && System.currentTimeMillis() >= previousAlgoExpiryTime) {
            log.debug("Cleaning up expired graceful algo instance");
            previousAlgoInstance.close();
            previousAlgoInstance = null;
        }
    }

    /**
     * 获取平滑过度的备用算法实例
     *
     * @return 如果存在且未过期则返回实例，否则返回null
     */
    private JwtAlgo getGracefulAlgo() {
        cleanupExpiredGracefulAlgo();
        return previousAlgoInstance;
    }

    // 供Renewal调用
    void recordBlacklistHit() {
        blacklistHitCount.incrementAndGet();
    }

    // 暴露指标
    public Map<String, Long> getMetrics() {
        return Map.of(
                "gracefulUsage", gracefulUsageCount.get(),
                "blacklistHit", blacklistHitCount.get()
        );
    }

    public void resetMetrics() {
        gracefulUsageCount.set(0);
        blacklistHitCount.set(0);
    }
}
