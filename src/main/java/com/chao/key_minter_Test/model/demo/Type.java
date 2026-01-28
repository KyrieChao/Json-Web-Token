package com.chao.key_minter_Test.model.demo;

import lombok.Data;

@Data
public class Type {
    private String type;
    private Integer n; //用于 HMAC
}
