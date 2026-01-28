package keyMinter.internal.core;

import keyMinter.config.KeyMinterProperties;
import keyMinter.internal.core.support.EcdsaJwt;
import keyMinter.internal.core.support.EddsaJwt;
import keyMinter.internal.core.support.HmacJwt;
import keyMinter.internal.core.support.RsaJwt;
import keyMinter.model.Algorithm;
import keyMinter.spi.SecretDirProvider;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWT 工厂
 * - 自动缓存实例
 * - 自动装载密钥
 * - 支持目录、文件、密钥轮换
 */
public class JwtFactory {
    private volatile int maxAlgoInstance = 5;   // 默认兜底
    private KeyMinterProperties properties;

    public void setProperties(KeyMinterProperties prop) {
        this.properties = prop;
        Integer val = prop.getMaxAlgoInstance();
        maxAlgoInstance = (val == null || val <= 0) ? 5 : val;
    }

    private final Map<String, JwtAlgo> CACHE =
            Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, JwtAlgo> eldest) {
                    if (size() > maxAlgoInstance) {
                        eldest.getValue().close();
                        return true;
                    }
                    return false;
                }
            });

    /**
     * 默认创建（HMAC256），启用轮换
     */
    public JwtAlgo get() {
        return get(Algorithm.HMAC256, (String) null);
    }

    /**
     * 创建指定算法的实例（默认目录，启用轮换）
     */
    public JwtAlgo get(Algorithm algorithm) {
        return get(algorithm, (String) null);
    }

    /**
     * 创建指定算法和目录的实例（指定轮换设置）
     */
    public JwtAlgo get(Algorithm algorithm, String directory) {
        return get(algorithm, directory != null ? Paths.get(directory) : null);
    }


    /**
     * 完整构造：算法 + 目录 + 轮换（核心方法）
     */
    public JwtAlgo get(Algorithm algorithm, Path keyDir) {
        String cacheKey = buildCacheKey(algorithm, keyDir);
        return CACHE.computeIfAbsent(cacheKey, key -> build(algorithm, keyDir));
    }

    /* -------------------------
     *  自动加载方法
     * ------------------------- */

    /**
     * 自动加载首个密钥（默认目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm) {
        return autoLoadFirstKey(algorithm, null, false);
    }

    /**
     * 自动加载首个密钥（强制重新加载）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    /**
     * 自动加载指定目录的首个密钥
     */
    public JwtAlgo autoLoad(Algorithm algorithm, Path directory) {
        return autoLoadFirstKey(algorithm, directory, false);
    }


    /**
     * 自动加载指定目录的首个密钥（字符串目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return autoLoadFirstKey(algorithm, directory != null ? Paths.get(directory) : null, false);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, false);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录，强制重新加载）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId, boolean force) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, force);
    }

    /**
     * 自动加载首个密钥的核心方法
     */
    private JwtAlgo autoLoadFirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, force);
    }

    /**
     * 自动加载指定密钥ID的核心方法
     */
    private JwtAlgo autoLoadWithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, keyId, force);
    }

    /* -------------------------
     *  私有方法
     * ------------------------- */

    /**
     * 构建缓存键
     */
    private String buildCacheKey(Algorithm algorithm, Path keyDir) {
        Path actualDir = resolveKeyDir(keyDir);
        String dirKey = actualDir != null
                ? actualDir.toAbsolutePath().toString()
                : SecretDirProvider.getDefaultBaseDir().toAbsolutePath().toString();
        return String.format("%s:%s", algorithm.name(), dirKey);
    }

    /**
     * 核心构造逻辑
     */
    private JwtAlgo build(Algorithm algorithm, Path keyDir) {
        KeyMinterProperties props = this.properties != null ? this.properties : new KeyMinterProperties();
        Path actualDir = resolveKeyDir(keyDir);
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> new HmacJwt(props, actualDir);
            case RSA256, RSA384, RSA512 -> new RsaJwt(props, actualDir);
            case ES256, ES384, ES512 -> new EcdsaJwt(props, actualDir);
            case Ed25519, Ed448 -> new EddsaJwt(props, actualDir);
        };
    }

    /**
     * 解析密钥目录：优先使用参数，其次使用配置，最后返回 null (由实现类决定默认值)
     */
    private Path resolveKeyDir(Path keyDir) {
        if (keyDir != null) return keyDir;
        if (this.properties != null && this.properties.getKeyDir() != null && !this.properties.getKeyDir().trim().isEmpty()) {
            return Paths.get(this.properties.getKeyDir().trim());
        }
        return null;
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public void clearCache() {
        CACHE.clear();
    }

    /**
     * 获取当前缓存大小
     */
    public int getCacheSize() {
        return CACHE.size();
    }
}
