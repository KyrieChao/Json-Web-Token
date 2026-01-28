package keyMinter.internal.core.support;

import keyMinter.internal.core.JwtAlgo;
import keyMinter.model.Algorithm;
import keyMinter.model.KeyVersion;

import java.nio.file.Path;
import java.util.Optional;

/**
 * 转接
 */
public class Prep {

    /**
     * 自动加载首个密钥的核心方法
     */
    public static JwtAlgo FirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);

        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, force);
        }
        return jwtAlgo;
    }

    /**
     * 自动加载指定密钥ID的核心方法
     */
    public static JwtAlgo WithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);

        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, keyId, force);
        }
        return jwtAlgo;
    }
    /**
     * 核心构造逻辑
     */
    private static JwtAlgo get(Algorithm algorithm, Path path) {
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> new HmacJwt(path);
            case RSA256, RSA384, RSA512 -> new RsaJwt(path);
            case ES256, ES384, ES512 -> new EcdsaJwt(path);
            case Ed25519, Ed448 -> new EddsaJwt(path);
        };
    }
}
