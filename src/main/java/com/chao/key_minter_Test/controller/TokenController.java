package com.chao.key_minter_Test.controller;

import com.chao.key_minter_Test.model.demo.*;
import com.chao.key_minter_Test.response.ApiResponse;
import com.chao.key_minter_Test.response.HTTPResponseCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.Resource;
import keyMinter.api.KeyMinter;
import keyMinter.internal.core.JwtAlgo;
import keyMinter.model.Algorithm;
import keyMinter.model.JwtProperties;
import keyMinter.model.JwtStandardInfo;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@Tag(name = "Global Key Management")
@Slf4j
public class TokenController {

    @Resource
    private KeyMinter key;
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${key-minter.admin-token:}")
    private String adminToken;

    private static final Logger AUDIT = LoggerFactory.getLogger("audit");

    private void requireAdmin(String provided) {
        if (adminToken == null || adminToken.isEmpty() || !adminToken.equals(provided)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "forbidden");
        }
    }

    @PostMapping("/add")
    @Operation(summary = "创建密钥（根据算法类型自动选择对称或非对称）")
    public ApiResponse<String> add(@RequestBody Type o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        boolean b;
        if (algorithm.isHmac()) {
            Integer n = o.getN() != null ? o.getN() : 64;
            b = key.createHmacKey(algorithm, n);
        } else {
            b = key.createKeyPair(algorithm);
        }
        AUDIT.info("action=create_key algorithm={} result={}", algorithm.name(), b);
        return ApiResponse.success(b + "");
    }

    @GetMapping("/get")
    @Operation(summary = "查询全局密钥信息与版本（无需指定类型）")
    public ApiResponse<Map<String, Object>> get() {
        Map<String, Object> map = new HashMap<>();
        map.put("keyInfo", key.getJwtProperties());
        map.put("CurveInfo", key.getECDCurveInfo());
        map.put("KeyVersions", key.getKeyVersions());
        map.put("size", key.getCacheSize());
        return ApiResponse.success(map);
    }

    @PostMapping("/switch")
    @Operation(summary = "全局切换指定算法与密钥ID")
    public ApiResponse<Void> switchTo(@RequestBody KeysType o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        String keyId = (o.getKey() == null || o.getKey().isEmpty()) ? null : o.getKey();
        key.switchTo(algorithm);
        if (keyId != null) {
            // Replaced autoLoadWithKeyId with autoLoad
            key.autoLoad(algorithm, null, keyId);
        } else {
            key.autoLoad(algorithm, true);
        }
        return ApiResponse.success();
    }

    @PostMapping("/session-token")
    @Operation(summary = "生成 JWT Token（使用会话密钥，无需类型）")
    public ApiResponse<String> sessionToken(@RequestBody User o) {
        if (!o.getUsername().equals("admin") || !o.getPassword().equals("123456")) {
            return ApiResponse.error(HTTPResponseCode.UNAUTHORIZED);
        }

        String sessionId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Duration ttl = Duration.ofMinutes(10);
        session s = session.builder()
                .session_id(sessionId)
                .session_key(o)
                .session_expires(now.plus(ttl))
                .build();
        redisTemplate.opsForValue().set("session:" + sessionId, s, Duration.ofMinutes(10));
        JwtProperties properties = JwtProperties.builder()
                .subject(sessionId)
                .issuer("demo")
                .expiration(now.plus(ttl)).build();
        String token = key.generateToken(properties);
        return ApiResponse.success(token);
    }

    @PostMapping("/session-get")
    @Operation(summary = "查询全局密钥信息与版本（无需指定类型）")
    public ApiResponse<Object> sessionGet(@RequestBody Token t) {
        JwtStandardInfo decoded = key.getStandardInfo(t.getToken());
        Map<String, Object> map = new LinkedHashMap<>();
        Object o = redisTemplate.opsForValue().get("session:" + decoded.getSubject());
        if (o == null) {
            return ApiResponse.error(HTTPResponseCode.UNAUTHORIZED);
        }
        map.put("info", o);
        map.put("expiration", key.decodeExpiration(t.getToken()));
        map.put("issuedAt", key.decodeIssuedAt(t.getToken()));
        return ApiResponse.success(map);
    }

    @GetMapping("/token")
    @Operation(summary = "生成 JWT Token（使用全局唯一密钥，无需类型）")
    public ApiResponse<String> token() {
        JwtProperties properties = JwtProperties.builder()
                .subject("sub")
                .issuer("issuer")
                .expiration(Instant.now().plus(Duration.ofMinutes(30))).build();
        String token = key.generateToken(properties, toUserInfo(), UserInfo.class);
        return ApiResponse.success(token);
    }

    @GetMapping("/verify")
    @Operation(summary = "校验 JWT Token（支持历史密钥）")
    public ApiResponse<String> verify(@RequestBody Token o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        return ApiResponse.success(key.verify(algorithm, o.getToken()) + "");
    }

    @GetMapping("/decode")
    @Operation(summary = "解析 JWT Token（标准与自定义信息，全局密钥）")
    public ApiResponse<Map<String, Object>> decode(@RequestBody Token o) {
        UserInfo userInfo = key.getCustomClaimsSafe(o.getToken(), UserInfo.class);
        JwtStandardInfo decoded = key.getStandardInfo(o.getToken());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("userInfo", userInfo);
        map.put("decoded", decoded);
        map.put("isDecodable", key.isTokenDecodable(o.getToken()));
        map.put("size", key.getCacheSize());
        return ApiResponse.success(map);
    }
    /*    @PostMapping("/refresh")
        @Operation(summary = "续签 JWT Token（全局密钥）")
        public ApiResponse<String> refresh(@RequestBody Token o) {
            String refreshed = key.refreshToken(o.getToken());
            if (refreshed == null) {
                AUDIT.info("action=refresh result=failed");
                return ApiResponse.error(HTTPResponseCode.NOT_IMPLEMENTED, "refresh not implemented or failed");
            }
            AUDIT.info("action=refresh result=success");
            return ApiResponse.success(refreshed);
        }

        @PostMapping("/revoke")
        @Operation(summary = "撤销 JWT Token（黑名单）")
        public ApiResponse<String> revoke(@RequestHeader(value = "X-Admin-Token", required = false) String admin, @RequestBody Token o) {
            requireAdmin(admin);
            boolean ok = key.revokeToken(o.getToken());
            AUDIT.info("action=revoke result={}", ok ? "success" : "failed");
            return ok ? ApiResponse.success("revoked") : ApiResponse.error(HTTPResponseCode.OPERATION_FAILED, "revoke failed");
        }*/

    @PostMapping("/activate")
    @Operation(summary = "全局激活指定算法与密钥ID")
    public ApiResponse<Map<String, Object>> activate(@RequestHeader(value = "X-Admin-Token", required = false) String admin,
                                                     @RequestBody KeysType o) {
        requireAdmin(admin);
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        String keyId = (o.getKey() == null || o.getKey().isEmpty()) ? null : o.getKey();
        key.switchTo(algorithm);
        // Replaced autoLoadWithKeyId with autoLoad
        JwtAlgo algo = key.autoLoad(algorithm, null, keyId);
        if (algo == null) {
            return ApiResponse.error(HTTPResponseCode.NOT_FOUND, "key not found");
        }
        AUDIT.info("action=activate algorithm={} keyId={}", algorithm.name(), keyId == null ? "null" : "***");
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("algorithm", algorithm.name());
        map.put("activeKeyVersions", key.getKeyVersions(algorithm, keyId));
        map.put("cacheSize", key.getCacheSize());
        return ApiResponse.success(map);
    }

    @PostMapping("/rotate")
    @Operation(summary = "触发自动化密钥轮换（不中断服务，保留历史密钥）")
    public ApiResponse<Map<String, Object>> rotate(@RequestHeader(value = "X-Admin-Token", required = false) String admin,
                                                   @RequestBody Type o) {
        requireAdmin(admin);
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        key.switchTo(algorithm);
        AUDIT.info("action=rotate algorithm={}", algorithm.name());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("algorithm", algorithm.name());
        map.put("keyInfo", key.getKeyInfo(algorithm, null));
        map.put("versions", key.getKeyVersions(algorithm, null));
        return ApiResponse.success(map);
    }

    @GetMapping("/versions")
    @Operation(summary = "查看全局密钥版本列表")
    public ApiResponse<Map<String, Object>> versions(@RequestHeader(value = "X-Admin-Token", required = false) String admin,
                                                     @RequestBody Type o) {
        requireAdmin(admin);
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("algorithm", algorithm.name());
        map.put("versions", key.listKeys());
        map.put("AllVersions", key.listAllKeys());
        return ApiResponse.success(map);
    }

    private static UserInfo toUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername("username");
        userInfo.setRole("admin");
        userInfo.setAge(18);
        userInfo.setActive(true);
        userInfo.setPreferences(new UserInfo.Preferences("dark", "en"));
        return userInfo;
    }
}
