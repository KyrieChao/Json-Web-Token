package com.chao.key_minter_Test.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginTokenDTO {
    private Long id;
    private Integer role;
}