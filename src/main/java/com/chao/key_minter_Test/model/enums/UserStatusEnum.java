package com.chao.key_minter_Test.model.enums;

import lombok.Getter;

/**
 * 角色枚举
 */
@Getter
public enum UserStatusEnum {
    ACTIVE(0, "正常"),
    DISABLED(1, "禁用"),
    WRITE_OFF(2, "已注销"),
    BANNED(3, "封禁"),
    DELETED(4, "已删除");

    private final int code;
    private final String desc;

    UserStatusEnum(int code, String desc) {
        this.code = code;
        this.desc = desc;
    }
}