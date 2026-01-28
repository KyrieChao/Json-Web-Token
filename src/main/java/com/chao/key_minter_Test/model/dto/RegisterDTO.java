package com.chao.key_minter_Test.model.dto;

import com.baomidou.mybatisplus.annotation.TableField;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;

/**
 * 用户表
 */
@Data
public class RegisterDTO implements Serializable {
    private String username;
    private String email;
    private String password;
    private String confirmPwd;
    private String avatar;
    private Integer role;
    @Serial
    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
}