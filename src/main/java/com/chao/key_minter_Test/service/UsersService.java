package com.chao.key_minter_Test.service;

import com.chao.key_minter_Test.model.dto.LoginDTO;
import com.chao.key_minter_Test.model.entity.Users;
import com.baomidou.mybatisplus.extension.service.IService;
import com.chao.key_minter_Test.model.dto.RegisterDTO;
import com.chao.key_minter_Test.model.vo.UserVO;

/**
* @author dell
* @description 针对表【users(用户表)】的数据库操作Service
* @createDate 2026-01-12 14:53:14
*/
public interface UsersService extends IService<Users> {

    boolean register(RegisterDTO user);

    UserVO login(LoginDTO dto);
}
