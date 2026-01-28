package com.chao.key_minter_Test.util;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class Helper {
    /**
     * 邮箱脱敏
     */
    public String mask(String email) {
        int at = email.indexOf('@');
        return email.substring(0, 2) + "***" + email.substring(at);
    }

    public String genUserName(int len) {
        return "chaoOJ" + UUID.randomUUID().toString().replace("-", "").substring(0, len);
    }

}