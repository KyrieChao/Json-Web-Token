package com.chao.key_minter_Test.encrypt;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.DigestUtils;

/**
 * 加密工具类
 */
public class Encoder {
    // BCrypt
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();
    // Argon2
    private static final Argon2PasswordEncoder ARGON_2_ENCODER =
            new Argon2PasswordEncoder(16, 32, 1, 1 << 12, 3);

    /**
     * BCrypt
     *
     * @param obj 需要加密的对象
     * @return 加密后的对象
     */
    public String encodeCode(String obj) {
        return ENCODER.encode(obj);
    }

    /**
     * BCrypt
     * 匹配
     *
     * @param userObj 需要匹配的编码
     * @param encoded 已加密的编码
     * @return 匹配结果
     */
    public boolean matchesCode(String userObj, String encoded) {
        return ENCODER.matches(userObj, encoded);
    }

    /**
     * Argon2
     *
     * @param obj 需要加密的对象
     * @return 加密后的对象
     */
    public String encodeArgon2(String obj) {
        return ARGON_2_ENCODER.encode(obj);
    }

    /**
     * Argon2
     *
     * @param userObj 需要匹配的编码
     * @param encoded 已加密的编码
     * @return 匹配结果
     */
    public boolean matchesArgon2(String userObj, String encoded) {
        return ARGON_2_ENCODER.matches(userObj, encoded);
    }

    /**
     * // todo 不推荐
     * 密码盐加密
     *
     * @param obj 需要加密的对象
     * @return 加密后的对象
     */
    public String saltEncode(String obj) {
        return DigestUtils.md5DigestAsHex(("chen893760" + obj).getBytes());
    }
}
