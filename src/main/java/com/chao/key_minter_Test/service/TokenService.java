package com.chao.key_minter_Test.service;

import com.chao.key_minter_Test.model.dto.SessionInfo;
import com.chao.key_minter_Test.model.vo.UserVO;
import keyMinter.api.KeyMinter;
import keyMinter.model.JwtProperties;
import keyMinter.model.JwtStandardInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final KeyMinter key;
    private final RedisTemplate<String, Object> redisTemplate;

    public String generateCustomToken(UserVO vo) {
        String sessionId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Duration ttl = Duration.ofMinutes(30);
        SessionInfo info = SessionInfo.builder()
                .id(sessionId)
                .key(vo)
                .expires(now.plus(ttl))
                .build();
        redisTemplate.opsForValue().set("session:" + sessionId, info, ttl);
        JwtProperties properties = JwtProperties.builder()
                .subject(sessionId)
                .issuer("chao")
                .expiration(now.plus(ttl)).build();
        return key.generateToken(properties);
    }

    public SessionInfo decodeCustomToken(String token) {
        JwtStandardInfo decoded = key.getStandardInfo(token);
        Object o = redisTemplate.opsForValue().get("session:" + decoded.getSubject());
        if (o == null) return null;
        return (SessionInfo) o;
    }
}
