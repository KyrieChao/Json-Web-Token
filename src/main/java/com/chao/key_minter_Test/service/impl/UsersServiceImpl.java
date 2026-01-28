package com.chao.key_minter_Test.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.chao.key_minter_Test.converter.CommonConverter;
import com.chao.key_minter_Test.encrypt.Encoder;
import com.chao.key_minter_Test.exception.Failure;
import com.chao.key_minter_Test.mapper.UsersMapper;
import com.chao.key_minter_Test.model.dto.LoginDTO;
import com.chao.key_minter_Test.model.dto.RegisterDTO;
import com.chao.key_minter_Test.model.entity.Users;
import com.chao.key_minter_Test.model.enums.RoleEnum;
import com.chao.key_minter_Test.model.enums.UserStatusEnum;
import com.chao.key_minter_Test.model.vo.UserVO;
import com.chao.key_minter_Test.response.HTTPResponseCode;
import com.chao.key_minter_Test.service.UsersService;
import com.chao.key_minter_Test.util.Helper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * @author dell
 * @description 针对表【users(用户表)】的数据库操作Service实现
 * @createDate 2026-01-12 14:53:14
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UsersServiceImpl extends ServiceImpl<UsersMapper, Users> implements UsersService {

    private final Encoder encoder = new Encoder();
    private final UsersMapper userMapper;
    private final Helper helper;

    @Override
    public boolean register(RegisterDTO dto) {
        Users users = new Users();
        Failure.state(dto.getConfirmPwd().equals(dto.getPassword())).orElse(HTTPResponseCode.USER_OPERATION_ERROR, "密码不一致");
        String email = dto.getEmail().trim().toLowerCase();
        Users exist = userMapper.selectOne(new LambdaQueryWrapper<Users>().eq(Users::getEmail, email));
        Failure.state(exist != null).orElse(HTTPResponseCode.PARAM_ERROR, "邮箱已存在");
        users.setUsername(helper.genUserName(10));
        users.setPassword(encoder.encodeCode(dto.getPassword()));
        users.setEmail(email);
        users.setAvatar(dto.getAvatar());
        users.setRole(RoleEnum.USER.getCode());
        boolean b = save(users);
        Failure.state(!b).orElse(HTTPResponseCode.USER_OPERATION_ERROR, "注册失败");
        return b;
    }

    @Override
    public UserVO login(LoginDTO dto) {
        String email = dto.getEmail().trim().toLowerCase();
        Failure.notBlank(dto.getPassword()).orElse(HTTPResponseCode.PARAM_ERROR, "密码不能为空")
                .notBlank(email).orElse(HTTPResponseCode.PARAM_ERROR, "邮箱不能为空");
        Users user = userMapper.selectOne(new LambdaQueryWrapper<Users>().eq(Users::getEmail, email));
        Failure.exists(user).orElse(HTTPResponseCode.NOT_FOUND, "邮箱错误");
        Failure.state(!encoder.matchesCode(dto.getPassword(), user.getPassword()))
                .orElse(HTTPResponseCode.USER_OPERATION_ERROR, "密码错误")
                .state(user.getStatus() != UserStatusEnum.ACTIVE.getCode())
                .state(user.getStatus() != UserStatusEnum.WRITE_OFF.getCode())
                .orElse(HTTPResponseCode.PARAM_ERROR, "该用户已被封禁");
        return CommonConverter.INSTANCE.User_VO(user);
    }
}




