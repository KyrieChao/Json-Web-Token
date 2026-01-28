package com.chao.key_minter_Test.model.enums;

import lombok.Getter;

@Getter
public enum RoleEnum {
    USER(0, "用户"),
    ADMIN(1, "管理员"),
    SUPER_ADMIN(2, "超级管理员"),
    ANONYMOUS(4, "匿名用户");

    private final int code;
    private final String desc;

    RoleEnum(int code, String desc) {
        this.code = code;
        this.desc = desc;
    }
}