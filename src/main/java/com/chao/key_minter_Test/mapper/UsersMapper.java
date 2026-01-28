package com.chao.key_minter_Test.mapper;

import com.chao.key_minter_Test.model.entity.Users;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
* @author dell
* @description 针对表【users(用户表)】的数据库操作Mapper
* @createDate 2026-01-12 14:53:14
* @Entity com.chao.key_minter_Test.model.entity.Users
*/
@Mapper
public interface UsersMapper extends BaseMapper<Users> {

}




