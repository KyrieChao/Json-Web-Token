package com.chao.keyminter.demo;

import keyMinter.api.KeyMinter;
import keyMinter.config.KeyMinterAutoConfiguration;
import keyMinter.model.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyMinter 全功能覆盖测试与使用示例
 */
@Slf4j
@SpringBootTest(classes = KeyMinterAutoConfiguration.class)
public class KeyMinterUsageTest {

    @Autowired
    private KeyMinter key;

    @Test
    @Order(1)
    @DisplayName("HMAC: Lifecycle and Basic Operations")
    void testHmacLifecycle() {
        // 1. Create Key
        boolean b = key.createHmacKey(Algorithm.HMAC256, 64);
        assertTrue(b);
        // 2. Switch
        boolean condition = key.switchTo(Algorithm.HMAC256);
        assertTrue(condition);
        // 3. Generate Token
        JwtProperties props = JwtProperties.builder()
                .subject("test-user")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();

        String token = key.generateToken(props);
        assertNotNull(token);

        // 4. Verify
        assertTrue(key.isValidToken(token));

        // 5. Decode
        JwtStandardInfo info = key.getStandardInfo(token);
        assertEquals("test-user", info.getSubject());
        assertEquals("test-issuer", info.getIssuer());

        // 6. Decode Map
        Map<String, Object> map = key.decodeToFullMap(token);
        assertEquals("test-user", map.get("sub"));

        // 7. Check Decodable
        assertTrue(key.isTokenDecodable(token));
    }

    @Test
    @DisplayName("1. 基础 Token 生成与验证 (HMAC)")
    void testBasicHmacFlow() {
        log.info("=== 测试 HMAC 基础流程 ===");
        // 1. 切换到 HMAC256
        key.switchTo(Algorithm.HMAC256);
        // 2. 准备 Token 属性
        JwtProperties props = JwtProperties.builder()
                .subject("user-123")
                .issuer("keyMinter-Test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();

        // 3. 生成 Token
        String token = key.generateToken(props);
        Assertions.assertNotNull(token);
        log.info("Generated HMAC Token: {}", token);

        // 4. 验证 Token
        boolean isValid = key.isValidToken(token);
        Assertions.assertTrue(isValid);

        // 5. 解析标准信息
        JwtStandardInfo info = key.getStandardInfo(token);
        Assertions.assertEquals("user-123", info.getSubject());
        Assertions.assertEquals("keyMinter-Test", info.getIssuer());
    }

    @Test
    @DisplayName("RSA: Lifecycle and Custom Claims")
    void testRsaLifecycle() {
        assertTrue(key.createKeyPair(Algorithm.RSA256));
        assertTrue(key.switchTo(Algorithm.RSA256));

        JwtProperties props = JwtProperties.builder()
                .subject("rsa-user")
                .issuer("test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();

        Map<String, Object> claims = Map.of("role", "admin", "id", 123);
        String token = key.generateToken(props, claims, Map.class);

        assertTrue(key.isValidToken(token));

        // Test Generic Decode
        Map decodedClaims = key.getCustomClaims(token, Map.class);
        assertEquals("admin", decodedClaims.get("role"));
        assertEquals(123, decodedClaims.get("id"));
    }

    @Test
    @DisplayName("ECDSA: Lifecycle and Curve Info")
    void testEcdsaLifecycle() {
        // Ensure a key exists in that directory (createKeyPair uses default/configured dir)
        if (!key.keyPairExists(Algorithm.ES256)) {
             assertTrue(key.createKeyPair(Algorithm.ES256));
        }

        // Ensure we are operating in the correct directory
        boolean condition = key.switchTo(Algorithm.ES256);
        assertTrue(condition);
        
        String token = key.generateToken(JwtProperties.builder().subject("ec").issuer("test").expiration(Instant.now().plus(Duration.ofMinutes(1))).build());
        assertTrue(key.isValidToken(token));

        String curveInfo = key.getECDCurveInfo();
        assertNotNull(curveInfo);
        assertTrue(curveInfo.contains("secp256r1") || curveInfo.contains("P-256"));
    }

    @Test
    @DisplayName("2. 携带自定义 Payload (RSA)")
    void testCustomPayloadWithRsa() {
        log.info("=== 测试 RSA 自定义载荷流程 ===");
        // 1. 切换到 RSA256 (会自动生成/加载密钥对)
        key.switchTo(Algorithm.RSA256);

        // 2. 准备自定义对象
        DemoUser user = new DemoUser();
        user.setId(10086L);
        user.setUsername("super_admin");
        user.setRoles(List.of("ADMIN", "EDITOR"));

        JwtProperties props = JwtProperties.builder()
                .subject("admin")
                .issuer("KeyMinter-Test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();

        // 3. 生成 Token
        String token = key.generateToken(props, user, DemoUser.class);
        Assertions.assertNotNull(token);
        log.info("Generated RSA Token: {}", token);

        // 4. 解析回对象
        DemoUser decodedUser = key.decodeToObject(token, DemoUser.class);
        Assertions.assertEquals(10086L, decodedUser.getId());
        Assertions.assertEquals("super_admin", decodedUser.getUsername());
        Assertions.assertTrue(decodedUser.getRoles().contains("ADMIN"));

        // 5. 获取完整信息
        JwtFullInfo<DemoUser> fullInfo = key.getFullInfo(token, DemoUser.class);
        Assertions.assertNotNull(fullInfo.getStandardInfo());
        Assertions.assertNotNull(fullInfo.getCustomClaims());
    }

    @Test
    @DisplayName("3. 算法热切换与平滑过渡")
    void testAlgorithmSwitching() {
        log.info("=== 测试算法热切换与平滑过渡 ===");

        // 1. 初始状态：HMAC
        key.switchTo(Algorithm.HMAC256);
        String hmacToken = key.generateToken(JwtProperties.builder()
                .subject("old-user")
                .issuer("KeyMinter-Test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1))).build());
        Assertions.assertTrue(key.isValidToken(hmacToken), "HMAC Token 应该有效");

        // 2. 切换算法：Ed25519
        log.info("切换算法到 Ed25519...");
        key.switchTo(Algorithm.Ed25519);
        // 确保有密钥可用
        if (!key.keyPairExists()) {
            key.createKeyPair(Algorithm.Ed25519);
            // 强制重新加载以确保 activeKeyId 更新
            key.autoLoad(Algorithm.Ed25519, true);
            // 再次确保切换成功
            key.switchTo(Algorithm.Ed25519);
        }

        // 3. 生成新 Token
        String edToken = key.generateToken(JwtProperties.builder()
                .subject("new-user")
                .issuer("KeyMinter-Test")
                .expiration(Instant.now().plusMillis(60000)).build());
        Assertions.assertTrue(key.isValidToken(edToken), "新算法 Token 应该有效");

        // 4. 验证旧 Token (平滑过渡)
        // KeyMinter 应该能识别出验证失败，并自动尝试使用旧算法(HMAC)验证
        boolean isOldTokenValid = key.isValidToken(hmacToken);
        Assertions.assertTrue(isOldTokenValid, "旧算法生成的 Token 在过渡期内应该依然有效");

        log.info("平滑过渡测试通过！");
    }

    @Test
    @DisplayName("4. 密钥管理与查询")
    void testKeyManagement() {
        log.info("=== 测试密钥管理 ===");

        // 1. 创建新密钥
        key.createHmacKey(Algorithm.HMAC512, 128);
        key.switchTo(Algorithm.HMAC512);

        // 2. 获取当前密钥信息
        String algoInfo = key.getAlgorithmInfo();
        String keyInfo = key.getJwtProperties();
        log.info("Current Algo: {}, Key Info: {}", algoInfo, keyInfo);
        Assertions.assertNotNull(algoInfo);

        // 3. 列出所有密钥版本
        List<KeyVersion> keys = key.listKeys();
        Assertions.assertFalse(keys.isEmpty());
        keys.forEach(k -> log.info("Found Key: {}", k));

        // 4. 检查当前使用的 Key ID
        String activeKeyId = key.getActiveKeyId();
        Assertions.assertNotNull(activeKeyId);
    }

    @Test
    @DisplayName("5. 各种解码方式测试")
    void testDecodingMethods() {
        key.switchTo(Algorithm.HMAC256);
        JwtProperties props = JwtProperties.builder()
                .subject("test-sub")
                .issuer("test-iss")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();
        String token = key.generateToken(props);

        // 1. decodeToFullMap
        Map<String, Object> map = key.decodeToFullMap(token);
        Assertions.assertEquals("test-sub", map.get("subject"));

        // 2. decodeIssuedAt
        Date issuedAt = key.decodeIssuedAt(token);
        Assertions.assertNotNull(issuedAt);

        // 3. decodeExpiration
        Date expiration = key.decodeExpiration(token);
        Assertions.assertNotNull(expiration);
        Assertions.assertTrue(expiration.after(new Date()));

        // 4. isTokenDecodable
        Assertions.assertTrue(key.isTokenDecodable(token));
        Assertions.assertFalse(key.isTokenDecodable("invalid-token-string"));
    }

    @Test
    @DisplayName("6. 测试switchTo")
    void testSwitchTo() throws InterruptedException {
        key.switchTo(Algorithm.ES256);
        Thread.sleep(2000);
        key.switchTo(Algorithm.Ed25519);
        String token = key.generateToken(JwtProperties.builder()
                .subject("old-user")
                .issuer("KeyMinter-Test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1))).build());
        log.info("Generated Token: {}", token);
    }

    // 模拟的自定义用户类
    @Data
    static class DemoUser {
        private Long id;
        private String username;
        private List<String> roles;
    }
}
