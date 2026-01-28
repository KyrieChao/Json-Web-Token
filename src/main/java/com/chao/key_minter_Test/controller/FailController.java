package com.chao.key_minter_Test.controller;

import com.chao.key_minter_Test.exception.Failure;
import com.chao.key_minter_Test.model.demo.Demo;
import com.chao.key_minter_Test.model.demo.Token;
import com.chao.key_minter_Test.model.dto.LoginDTO;
import com.chao.key_minter_Test.model.dto.SessionInfo;
import com.chao.key_minter_Test.model.vo.UserVO;
import com.chao.key_minter_Test.response.ApiResponse;
import com.chao.key_minter_Test.response.HTTPResponseCode;
import com.chao.key_minter_Test.service.TokenService;
import com.chao.key_minter_Test.service.UsersService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/fail")
@RequiredArgsConstructor
public class FailController {

    private final UsersService userService;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ApiResponse<String> login(@RequestBody LoginDTO dto) {
        UserVO vo = userService.login(dto);
        String token = tokenService.generateCustomToken(vo);
        return ApiResponse.success(token);
    }

    @GetMapping("/info")
    public ApiResponse<SessionInfo> info(@RequestBody Token t) {
        SessionInfo vo = tokenService.decodeCustomToken(t.getToken());
        Failure.state(vo != null).orElse(HTTPResponseCode.UNAUTHORIZED, "无数据！");
        return ApiResponse.success(vo);
    }


    @PostMapping("/test")
    public ApiResponse<String> test(@RequestBody(required = false) Demo d) {
        Failure.exists(d).orElse(HTTPResponseCode.DATA_NOT_FOUND)
                .notEmpty(d.getName()).orElse(HTTPResponseCode.QUERY_FAILED)
                .state(d.getAge() < 18).orElse(HTTPResponseCode.CONTINUE);
        return ApiResponse.success("ok");
    }
}
