package com.chao.key_minter_Test.converter;


import com.chao.key_minter_Test.model.entity.Users;
import com.chao.key_minter_Test.model.vo.UserVO;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface CommonConverter {
    CommonConverter INSTANCE = Mappers.getMapper(CommonConverter.class);

    UserVO User_VO(Users user);
}