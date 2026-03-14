package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.chao.keyMinter.domain.service.JwtAlgo;
import io.jsonwebtoken.JwtBuilder;
import org.mockito.MockedStatic;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AbstractJwtAlgoTest {

    @TempDir
    Path tempDir;

    private TestJwtAlgo jwtAlgo;
    private KeyMinterProperties properties;

    @BeforeEach
    void setUp() {
        properties = new KeyMinterProperties();
        properties.setKeyValidityDays(1);
        properties.setEnableRotation(true);
        jwtAlgo = new TestJwtAlgo(properties, tempDir);
    }

    @Test
    void testValidateJwtProperties_Valid() {
        // Arrange
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));

        // Act & Assert
        assertDoesNotThrow(() -> jwtAlgo.validateJwtProperties(props), "Valid properties should pass validation");
    }

    @Test
    void testValidateJwtProperties_Invalid() {
        // Arrange
        JwtProperties props = new JwtProperties();
        
        // Act & Assert - Null props
        assertThrows(NullPointerException.class, () -> jwtAlgo.validateJwtProperties(null), "Null properties should throw NPE");

        // Missing Subject
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Missing subject should throw IllegalArgumentException");

        // Missing Issuer
        props.setSubject("sub");
        props.setIssuer("");
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Empty issuer should throw IllegalArgumentException");

        // Missing Expiration
        props.setIssuer("iss");
        props.setExpiration(null);
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Null expiration should throw IllegalArgumentException");

        // Past Expiration
        props.setExpiration(Instant.now().minusSeconds(3600));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Past expiration should throw IllegalArgumentException");
    }

    @Test
    void testCheckActiveKeyCanSign_NoKey() {
        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertEquals("No active key. Call setActiveKey or rotateKey first.", ex.getMessage());
    }

    @Test
    void testCheckActiveKeyCanSign_KeyNotFound() {
        // Arrange
        // Manually set activeKeyId without adding to map (simulating inconsistent state)
        jwtAlgo.setActiveKeyIdDirectly("non-existent-key");

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key version not found"));
    }

    @Test
    void testCheckActiveKeyCanSign_Expired() {
        // Arrange
        String keyId = "expired-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(10))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key has expired"));
    }

    @Test
    void testCheckActiveKeyCanSign_Revoked() {
        // Arrange
        String keyId = "revoked-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.REVOKED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key cannot be used for signing"));
    }

    @Test
    void testSetActiveKey_InvalidInput() {
        // Act & Assert
        assertFalse(jwtAlgo.setActiveKey(null), "Null keyId should return false");
        assertFalse(jwtAlgo.setActiveKey(""), "Empty keyId should return false");
        assertFalse(jwtAlgo.setActiveKey("non-existent"), "Non-existent keyId should return false");
    }

    @Test
    void testSetActiveKey_ExpiredOrRevoked() {
        // Arrange
        String expiredKey = "expired";
        KeyVersion expVersion = KeyVersion.builder()
                .keyId(expiredKey)
                .status(KeyStatus.EXPIRED) // Status is EXPIRED
                .expiresAt(Instant.now().minusSeconds(10)) // Actually expired
                .build();
        jwtAlgo.addKeyVersion(expVersion);

        String revokedKey = "revoked";
        KeyVersion revVersion = KeyVersion.builder()
                .keyId(revokedKey)
                .status(KeyStatus.REVOKED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(revVersion);

        // Act & Assert
        assertFalse(jwtAlgo.setActiveKey(expiredKey), "Setting expired key should fail");
        assertFalse(jwtAlgo.setActiveKey(revokedKey), "Setting revoked key should fail");
    }

    @Test
    void testConvertToClaimsMap() {
        // 1. Null
        assertNull(jwtAlgo.convertToClaimsMap(null));

        // 2. Map
        Map<String, Object> map = new HashMap<>();
        map.put("foo", "bar");
        assertEquals(map, jwtAlgo.convertToClaimsMap(map));

        // 3. String (JSON)
        String json = "{\"foo\":\"bar\"}";
        Map<String, Object> result = jwtAlgo.convertToClaimsMap(json);
        assertEquals("bar", result.get("foo"));

        // 4. Object (POJO)
        TestClaims claims = new TestClaims("bar");
        result = jwtAlgo.convertToClaimsMap(claims);
        assertEquals("bar", result.get("foo"));

        // 5. Invalid JSON String
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.convertToClaimsMap("{invalid-json}"));
    }
    
    @Test
    void testAutoLoadKey_PreferredNotFound() {
        // Arrange
        String preferred = "preferred-key";
        
        // Act
        jwtAlgo.autoLoadKey(preferred);
        
        // Assert
        assertNull(jwtAlgo.getActiveKeyId(), "Should not set active key if preferred key not found");
    }

    @Test
    void testAutoLoadKey_PreferredExpired() {
        // Arrange
        String preferred = "preferred-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(preferred)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(100))
                .build();
        jwtAlgo.addKeyVersion(version);
        
        // Act
        jwtAlgo.autoLoadKey(preferred);
        
        // Assert
        // Logic: if expired, logs warning and returns (does not activate)
        // Since we didn't set it active before, activeKeyId should be null
        // But wait, autoLoadKey checks: if (keyVersions.containsKey) { if expired { log; return; } setActiveKey... }
        // So it should NOT activate.
        assertNull(jwtAlgo.getActiveKeyId(), "Should not activate expired preferred key");
    }

    @Test
    void testCleanupExpiredKeys_InMemoery() {
        // Arrange
        String expiredKey = "expired-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(expiredKey)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(100))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(expiredKey);
        
        // Act
        jwtAlgo.cleanupExpiredKeys();
        
        // Assert
        assertEquals(KeyStatus.EXPIRED, version.getStatus());
    }

    @Test
    void testGetKeyInfo() {
        // Arrange
        String keyId = "test-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);
        
        // Act
        String info = jwtAlgo.getKeyInfo();
        
        // Assert
        assertNotNull(info);
        assertTrue(info.contains(keyId));
        assertTrue(info.contains("ACTIVE"));
    }

    @Test
    void testDefaultMethods() {
        // manageSecret
        assertFalse(jwtAlgo.manageSecret("secret"));
        
        // rotateKeyWithTransition - should throw because rotation is enabled but not implemented in test subclass?
        // Wait, base class throws UnsupportedOperationException if not enabled, or logs warn and returns false.
        // My properties have rotation enabled.
        // Base class:
        // if (!isKeyRotationEnabled()) throw ...
        // log.warn(...)
        // return false;
        assertFalse(jwtAlgo.rotateKeyWithTransition(Algorithm.HMAC256, "new-key", 24));
        
        // If rotation disabled
        properties.setEnableRotation(false);
        assertThrows(UnsupportedOperationException.class, () -> jwtAlgo.rotateKeyWithTransition(Algorithm.HMAC256, "new-key", 24));
    }
    
    @Test
    void testGetDirTimestamp() {
        // Valid
        Path p1 = tempDir.resolve("HMAC256-v20230101-120000-12345678");
        assertDoesNotThrow(() -> jwtAlgo.getDirTimestamp(p1));
        
        // Invalid
        Path p2 = tempDir.resolve("invalid-name");
        assertEquals(java.time.LocalDateTime.MIN, jwtAlgo.getDirTimestamp(p2));
    }

    @Test
    void testGetKeyVersions_and_filters() {
        // Arrange
        KeyVersion h1 = KeyVersion.builder().keyId("h1").algorithm(Algorithm.HMAC256).status(KeyStatus.CREATED).build();
        KeyVersion r1 = KeyVersion.builder().keyId("r1").algorithm(Algorithm.RSA256).status(KeyStatus.REVOKED).build();
        jwtAlgo.addKeyVersion(h1);
        jwtAlgo.addKeyVersion(r1);

        // Act
        List<String> all = jwtAlgo.getKeyVersions();
        List<String> hmacOnly = jwtAlgo.getKeyVersions(Algorithm.HMAC256);
        List<String> nullAlgo = jwtAlgo.getKeyVersions((Algorithm) null);
        List<String> revoked = jwtAlgo.getKeyVersionsByStatus(KeyStatus.REVOKED);
        List<String> nullStatus = jwtAlgo.getKeyVersionsByStatus(null);

        // Assert
        assertTrue(all.containsAll(List.of("h1", "r1")));
        assertEquals(List.of("h1"), hmacOnly);
        assertEquals(Collections.emptyList(), nullAlgo);
        assertEquals(List.of("r1"), revoked);
        assertEquals(Collections.emptyList(), nullStatus);
    }

    @Test
    void testGetActiveKeyVersion_when_no_active_returns_null() {
        // Arrange
        jwtAlgo.setActiveKeyIdDirectly(null);

        // Act
        KeyVersion active = jwtAlgo.getActiveKeyVersion();

        // Assert
        assertNull(active);
    }

    @Test
    void testSetActiveKey_success_sets_transition_for_old_key_and_activates_new() {
        // Arrange
        properties.setTransitionPeriodHours(1);
        KeyVersion oldKey = KeyVersion.builder()
                .keyId("old")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        KeyVersion newKey = KeyVersion.builder()
                .keyId("new")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(oldKey);
        jwtAlgo.addKeyVersion(newKey);
        jwtAlgo.setActiveKeyIdDirectly("old");

        // Act
        boolean ok = jwtAlgo.setActiveKey("new");

        // Assert
        assertTrue(ok);
        assertEquals("new", jwtAlgo.getActiveKeyId());
        assertEquals(KeyStatus.ACTIVE, jwtAlgo.getActiveKeyVersion().getStatus());
        assertEquals(KeyStatus.TRANSITIONING, oldKey.getStatus());
        assertNotNull(oldKey.getTransitionEndsAt());
    }

    @Test
    void testSetActiveKey_when_loadKeyPair_throws_returns_false() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setLoadKeyPairFailure(true);

        // Act
        boolean ok = jwtAlgo.setActiveKey("k1");

        // Assert
        assertFalse(ok);
    }

    @Test
    void testCanKeyVerify_transitioning_key_past_transition_end_is_deactivated() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("t1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.TRANSITIONING)
                .expiresAt(Instant.now().plusSeconds(3600))
                .transitionEndsAt(Instant.now().minusSeconds(5))
                .build();
        jwtAlgo.addKeyVersion(version);

        // Act
        boolean canVerify = jwtAlgo.canKeyVerify("t1");

        // Assert
        assertFalse(canVerify);
        assertEquals(KeyStatus.INACTIVE, version.getStatus());
    }

    @Test
    void testValidateDirectoryPath_rejects_non_normalized_and_symlink() {
        // Arrange
        Path nonNormalized = Path.of("a", "..", "b");

        // Act & Assert
        assertThrows(SecurityException.class, () -> jwtAlgo.validateDirectoryPath(nonNormalized));

        Path normalized = Path.of("b");
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.isSymbolicLink(normalized)).thenReturn(true);
            assertThrows(SecurityException.class, () -> jwtAlgo.validateDirectoryPath(normalized));
        }
    }

    @Test
    void testFindKeyDir_returns_latest_matching_dir_and_handles_interrupt_and_io_error() throws Exception {
        // Arrange
        Path dir = Files.createDirectories(tempDir.resolve("scan"));
        jwtAlgo.setCurrentKeyPath(dir);

        Files.createDirectories(dir.resolve("hmac-v20240101-120000-a"));
        Files.createDirectories(dir.resolve("hmac-v20240102-120000-b"));

        // Act
        Optional<Path> latest = jwtAlgo.callFindKeyDir("HMAC", null);

        // Assert
        assertTrue(latest.isPresent());
        assertEquals("hmac-v20240102-120000-b", latest.get().getFileName().toString());

        // Arrange (Interrupted sleep path)
        jwtAlgo.setCurrentKeyPath(dir.resolve("empty"));
        Files.createDirectories(jwtAlgo.getCurrentKeyPath());
        Thread.currentThread().interrupt();

        // Act
        Optional<Path> interruptedResult = jwtAlgo.callFindKeyDir("HMAC", null);

        // Assert
        assertTrue(interruptedResult.isEmpty());
        Thread.interrupted();

        // Arrange (I/O error path)
        jwtAlgo.setCurrentKeyPath(dir.resolve("ioerr"));
        Files.createDirectories(jwtAlgo.getCurrentKeyPath());
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(jwtAlgo.getCurrentKeyPath())).thenReturn(true);
            files.when(() -> Files.list(jwtAlgo.getCurrentKeyPath())).thenThrow(new java.io.IOException("boom"));

            // Act
            Optional<Path> ioError = jwtAlgo.callFindKeyDir("HMAC", null);

            // Assert
            assertTrue(ioError.isEmpty());
        }
    }

    @Test
    void testUpdateKeyStatusFile_when_repo_missing_or_ioexception_does_not_throw() throws Exception {
        // Arrange
        jwtAlgo.setKeyRepository(null);

        // Act & Assert
        assertDoesNotThrow(() -> jwtAlgo.callUpdateKeyStatusFile("k1", KeyStatus.ACTIVE));

        KeyRepository repo = Mockito.mock(KeyRepository.class);
        Mockito.doThrow(new java.io.IOException("io")).when(repo).saveMetadata(Mockito.eq("k1"), Mockito.eq("status.info"), Mockito.anyString());
        jwtAlgo.setKeyRepository(repo);

        assertDoesNotThrow(() -> jwtAlgo.callUpdateKeyStatusFile("k1", KeyStatus.ACTIVE));
    }

    @Test
    void testMarkKeyActive_covers_missing_version_and_repo_paths() throws Exception {
        // Arrange
        jwtAlgo.setKeyRepository(null);

        // Act & Assert (missing version)
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("missing"));

        // Arrange (repo null path with existing version)
        KeyVersion v = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(v);
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("k1"));

        // Arrange (repo present but throws IOException)
        KeyRepository repo = Mockito.mock(KeyRepository.class);
        Mockito.doThrow(new java.io.IOException("io")).when(repo).saveMetadata(Mockito.eq("k1"), Mockito.eq("status.info"), Mockito.anyString());
        jwtAlgo.setKeyRepository(repo);
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("k1"));
    }

    @Test
    void testAutoLoadFirstKey_when_no_key_files_sets_active_null() {
        // Arrange
        jwtAlgo.setActiveKeyIdDirectly("will-clear");

        // Act
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, null, false);

        // Assert
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testAutoLoadKey_when_present_and_not_expired_activates() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);

        // Act
        jwtAlgo.autoLoadKey("k1");

        // Assert
        assertEquals("k1", jwtAlgo.getActiveKeyId());
    }

    @Test
    void testAutoLoadKey_when_current_key_path_null_is_handled() {
        // Arrange
        jwtAlgo.setCurrentKeyPath(null);

        // Act
        jwtAlgo.autoLoadKey("k1");

        // Assert
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testListAllKeys_scans_directories_and_handles_invalid_inputs_and_exceptions() throws Exception {
        // Arrange
        Path baseDir = Files.createDirectories(tempDir.resolve("base"));
        Path typeDir = Files.createDirectories(baseDir.resolve("unknown-keys"));
        Path v1 = Files.createDirectories(typeDir.resolve("unknown-v20240101-120000-a"));

        Files.writeString(v1.resolve("status.info"), "NOT_A_STATUS");
        Files.writeString(v1.resolve("expiration.info"), "NOT_AN_INSTANT");

        // Act
        List<KeyVersion> empty1 = jwtAlgo.listAllKeys((String) null);
        List<KeyVersion> empty2 = jwtAlgo.listAllKeys("");
        List<KeyVersion> empty3 = jwtAlgo.listAllKeys(tempDir.resolve("missing").toString());
        List<KeyVersion> keys = jwtAlgo.listAllKeys(baseDir.toString());

        // Assert
        assertEquals(Collections.emptyList(), empty1);
        assertEquals(Collections.emptyList(), empty2);
        assertEquals(Collections.emptyList(), empty3);
        assertEquals(1, keys.size());
        assertEquals("unknown-v20240101-120000-a", keys.get(0).getKeyId());
        assertEquals(Algorithm.HMAC256, keys.get(0).getAlgorithm());
        assertEquals(KeyStatus.CREATED, keys.get(0).getStatus());
        assertNull(keys.get(0).getExpiresAt());

        // Arrange (I/O exception path)
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            Path anyPath = Path.of("io-base");
            files.when(() -> Files.exists(anyPath)).thenReturn(true);
            files.when(() -> Files.isDirectory(anyPath)).thenReturn(true);
            files.when(() -> Files.list(anyPath)).thenThrow(new java.io.IOException("boom"));

            // Act
            List<KeyVersion> ioKeys = jwtAlgo.listAllKeys(anyPath.toString());

            // Assert
            assertEquals(Collections.emptyList(), ioKeys);
        }
    }

    @Test
    void testGetDirTimestamp_reads_created_time_from_version_json() throws Exception {
        // Arrange
        Path dir = Files.createDirectories(tempDir.resolve("any-v20240101-120000-a"));
        Files.writeString(dir.resolve("version.json"), "{\"createdTime\":\"2024-01-01T10:15:30\"}");

        // Act
        LocalDateTime ts = jwtAlgo.getDirTimestamp(dir);

        // Assert
        assertEquals(LocalDateTime.parse("2024-01-01T10:15:30"), ts);
    }

    @Test
    void testConvertToClaimsMap_object_conversion_failure_throws() {
        // Arrange
        class Node {
            public Node next;
        }
        Node n = new Node();
        n.next = n;

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.convertToClaimsMap(n));
    }

    @Test
    void testToDate_null_throws_and_non_null_converts() {
        // Arrange
        Instant now = Instant.now();

        // Act & Assert
        assertThrows(NullPointerException.class, () -> AbstractJwtAlgo.toDate(null));
        assertEquals(now.toEpochMilli(), AbstractJwtAlgo.toDate(now).toInstant().toEpochMilli());
    }

    @Test
    void testListAllKeys_uses_parent_dot_when_current_key_path_has_no_parent(@TempDir Path workDir) throws Exception {
        // Arrange
        String oldUserDir = System.getProperty("user.dir");
        System.setProperty("user.dir", workDir.toString());
        try {
            Path base = Files.createDirectories(workDir.resolve("base"));
            Path relativeKeyPath = Path.of("hmac-keys");
            Files.createDirectories(workDir.resolve(relativeKeyPath));
            jwtAlgo.setCurrentKeyPath(relativeKeyPath);

            // Act
            List<KeyVersion> result = jwtAlgo.listAllKeys();

            // Assert
            assertNotNull(result);
        } finally {
            System.setProperty("user.dir", oldUserDir);
        }
    }

    @Test
    void testClose_is_idempotent() {
        // Arrange & Act
        jwtAlgo.close();
        jwtAlgo.close();

        // Assert
        assertTrue(true);
    }

    @Test
    void testGenerateToken_2Args() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));
        
        // Ensure active key so validation passes
        KeyVersion kv = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .keyPath("k1")
                .build();
        jwtAlgo.addKeyVersion(kv);
        jwtAlgo.setActiveKeyIdDirectly("k1");

        String token = jwtAlgo.generateToken(props, Algorithm.HMAC256);
        assertEquals("dummy-token", token);
    }

    @Test
    void testGetKeyVersions_Algorithm_Empty() {
        // jwtAlgo starts with empty keyVersions
        List<String> versions = jwtAlgo.getKeyVersions(Algorithm.HMAC256);
        assertNotNull(versions);
        assertTrue(versions.isEmpty());
    }

    @Test
    void testLombokGetters() {
        assertNotNull(jwtAlgo.getRevokedFingerprints());
        
        assertNotNull(jwtAlgo.getActiveKeyLock());
        assertNotNull(jwtAlgo.getReadLock());
        assertNotNull(jwtAlgo.getWriteLock());
        
        // repositoryFactory is null by default in test setup unless set
        assertNull(jwtAlgo.getRepositoryFactory());
        
        assertNotNull(jwtAlgo.getKeyMinterProperties());
        
        // activeKeyId is null initially
        assertNull(jwtAlgo.getActiveKeyId());
        
        // currentKeyPath set in constructor
        assertNotNull(jwtAlgo.getCurrentKeyPath());
        
        // keyRepository null initially
        assertNull(jwtAlgo.getKeyRepository());
        
        // keyRotationEnabled is true in setup
        assertTrue(jwtAlgo.isKeyRotationEnabled());
        
        assertNotNull(jwtAlgo.getDefaultNewExpMs());
    }

    @Test
    void testCleanupExpiredKeys() {
        // 1. Expired key
        KeyVersion expired = KeyVersion.builder()
                .keyId("expired-key")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(expired);

        // 2. Transitioning key ended
        KeyVersion transitioning = KeyVersion.builder()
                .keyId("trans-key")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.TRANSITIONING)
                .transitionEndsAt(Instant.now().minusSeconds(10))
                .build();
        jwtAlgo.addKeyVersion(transitioning);

        // 3. Active key expired -> auto switch
        jwtAlgo.setActiveKeyIdDirectly("expired-key");
        KeyVersion newKey = KeyVersion.builder()
                .keyId("new-key")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(newKey);

        // Act
        jwtAlgo.cleanupExpiredKeys();

        // Assert
        assertEquals(KeyStatus.EXPIRED, expired.getStatus());
        assertEquals(KeyStatus.INACTIVE, transitioning.getStatus());
        assertEquals("new-key", jwtAlgo.getActiveKeyId());
        assertEquals(KeyStatus.ACTIVE, newKey.getStatus());
    }

    @Test
    void testAutoLoadKey() {
        // 1. Existing in memory
        KeyVersion k1 = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(k1);
        
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "k1", false);
        assertEquals("k1", jwtAlgo.getActiveKeyId());
        
        // 2. Not in memory (should try disk, fail gracefully)
        jwtAlgo.setActiveKeyIdDirectly(null);
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "missing", false);
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testListAllKeys_And_DirectoryDetection() throws Exception {
        // Setup directory structure
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir); // Point directly to type dir as per implementation?
        // AbstractJwtAlgo.listAllKeys() logic:
        // if currentKeyPath != null: parent = currentKeyPath.getParent(); listAllKeys(parent)
        // If currentKeyPath is ".../hmac-keys", parent is "...".
        // listAllKeys(parent) iterates subdirs of parent. One of them is "hmac-keys".
        // Inside "hmac-keys", it iterates version dirs.
        
        // So if tempDir is the parent, and we set currentKeyPath to tempDir/hmac-keys.
        
        String verDirName = "HMAC256-v20230101-120000-12345678";
        Path verDir = typeDir.resolve(verDirName);
        Files.createDirectories(verDir);
        
        // Create metadata files
        Files.writeString(verDir.resolve("status.info"), "CREATED");
        Files.writeString(verDir.resolve("algorithm.info"), "HMAC256");
        
        // Act
        List<KeyVersion> keys = jwtAlgo.listAllKeys();
        
        // Assert
        assertFalse(keys.isEmpty());
        KeyVersion k = keys.stream().filter(v -> v.getKeyId().equals(verDirName)).findFirst().orElse(null);
        assertNotNull(k);
        assertEquals(Algorithm.HMAC256, k.getAlgorithm());
        assertEquals(KeyStatus.CREATED, k.getStatus());
    }

    @Test
    void testAdditionalMethods() {
        // 1. getKeyInfo
        assertNotNull(jwtAlgo.getKeyInfo());
        jwtAlgo.setActiveKeyIdDirectly("k1");
        assertNotNull(jwtAlgo.getKeyInfo());

        // 2. keyPairExists
        assertFalse(jwtAlgo.keyPairExists());
        assertFalse(jwtAlgo.keyPairExists(Algorithm.HMAC256));
        
        KeyVersion k1 = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(k1);
        
        assertTrue(jwtAlgo.keyPairExists());
        assertTrue(jwtAlgo.keyPairExists(Algorithm.HMAC256));
        assertFalse(jwtAlgo.keyPairExists(Algorithm.RSA256));
        assertFalse(jwtAlgo.keyPairExists(null));

        // 3. withKeyDirectory
        Path newDir = tempDir.resolve("new-keys");
        jwtAlgo.withKeyDirectory(newDir);
        assertEquals(newDir, jwtAlgo.getCurrentKeyPath());
        assertNotNull(jwtAlgo.getKeyRepository());

        // 4. canKeyVerify / canKeyNotVerify
        assertFalse(jwtAlgo.callCanKeyVerify(null));
        assertFalse(jwtAlgo.callCanKeyVerify("missing"));
        assertTrue(jwtAlgo.callCanKeyNotVerify("missing"));
        
        assertTrue(jwtAlgo.callCanKeyVerify("k1"));
        assertFalse(jwtAlgo.callCanKeyNotVerify("k1"));

        // 5. Validation methods
        assertDoesNotThrow(() -> jwtAlgo.callValidateHmacAlgorithm(Algorithm.HMAC256));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.callValidateHmacAlgorithm(Algorithm.RSA256));

        assertDoesNotThrow(() -> jwtAlgo.callValidateRsaAlgorithm(Algorithm.RSA256));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.callValidateRsaAlgorithm(Algorithm.HMAC256));

        assertDoesNotThrow(() -> jwtAlgo.callValidateEcdsaAlgorithm(Algorithm.ES256));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.callValidateEcdsaAlgorithm(Algorithm.HMAC256));

        assertDoesNotThrow(() -> jwtAlgo.callValidateEddsaAlgorithm(Algorithm.Ed25519));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.callValidateEddsaAlgorithm(Algorithm.HMAC256));
    }

    @Test
    void testListAllKeys_WithNonDirectoryFiles() throws Exception {
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir);
        
        Files.createFile(typeDir.resolve("ignore-me.txt"));
        
        Path verDir = typeDir.resolve("HMAC256-v20230101-120000-12345678");
        Files.createDirectories(verDir);
        Files.writeString(verDir.resolve("status.info"), "CREATED");
        Files.writeString(verDir.resolve("algorithm.info"), "HMAC256");
        
        Files.createFile(verDir.resolve("ignore-file-inside.txt"));
        
        List<KeyVersion> keys = jwtAlgo.listAllKeys();
        assertEquals(1, keys.size());
    }

    @Test
    void testReadKeyStatus_Repository() throws Exception {
        KeyRepository repo = Mockito.mock(KeyRepository.class);
        jwtAlgo.setKeyRepository(repo);
        
        Mockito.when(repo.loadMetadata(anyString(), eq("status.info"))).thenReturn(Optional.of("ACTIVE"));
        Mockito.when(repo.loadMetadata(anyString(), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(3600).toString()));
        Mockito.when(repo.loadMetadata(anyString(), eq("transition.info"))).thenReturn(Optional.empty());
        Mockito.when(repo.loadMetadata(anyString(), eq("algorithm.info"))).thenReturn(Optional.of("HMAC256"));

        // Trigger loading via listAllKeys which calls createKeyVersionFromDir
        // But createKeyVersionFromDir uses repository if set?
        // Yes, readKeyStatus checks keyRepository.
        
        // We need to fake the directory iteration or just call listAllKeys with a real directory structure
        // but verify it uses the repo for metadata.
        
        try {
            Path typeDir = tempDir.resolve("hmac-keys");
            Files.createDirectories(typeDir);
            jwtAlgo.setCurrentKeyPath(typeDir);
            Path verDir = typeDir.resolve("k1");
            Files.createDirectories(verDir);
            
            List<KeyVersion> keys = jwtAlgo.listAllKeys();
            assertEquals(1, keys.size());
            assertEquals(KeyStatus.ACTIVE, keys.get(0).getStatus());
            assertEquals(Algorithm.HMAC256, keys.get(0).getAlgorithm());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testAutoLoadKey_ExpiredInMemory() {
        KeyVersion k1 = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(k1);
        
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "k1", false);
        // Should NOT be active if expired
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testAutoLoadKey_DiskLoad_Valid_And_Expired() throws Exception {
        // Valid
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir);
        
        Path k1Dir = typeDir.resolve("k1");
        Files.createDirectories(k1Dir);
        
        // Setup TestJwtAlgo to "load" this key when asked
        jwtAlgo.setKeyToLoadOnDisk("k1", KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());
        
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "k1", false);
        assertEquals("k1", jwtAlgo.getActiveKeyId());
        
        // Expired on disk
        Path k2Dir = typeDir.resolve("k2");
        Files.createDirectories(k2Dir);
        jwtAlgo.setKeyToLoadOnDisk("k2", KeyVersion.builder()
                .keyId("k2")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build());
        
        // Reset active
        jwtAlgo.setActiveKeyIdDirectly(null);
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "k2", false);
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testGetKeyVersionsByStatus_Null_Empty() {
        assertTrue(jwtAlgo.getKeyVersionsByStatus(null).isEmpty());
        assertTrue(jwtAlgo.getKeyVersionsByStatus(KeyStatus.ACTIVE).isEmpty());
    }

    @Test
    void testCreateJwtBuilder() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));
        
        jwtAlgo.setActiveKeyIdDirectly("k1");
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        
        JwtBuilder builder = jwtAlgo.callCreateJwtBuilder(props, claims);
        assertNotNull(builder);
        // Can't easily inspect builder content without building, but assume it worked if no exception
    }

    @Test
    void testDeleteKeyDirectory_Fallback() throws Exception {
        // Setup a key version and directory
        Path keyDir = tempDir.resolve("hmac-keys").resolve("k-del");
        Files.createDirectories(keyDir);
        Files.writeString(keyDir.resolve("test.txt"), "data");
        
        KeyVersion kv = KeyVersion.builder()
                .keyId("k-del")
                .keyPath(keyDir.toString())
                .build();
        
        // Ensure repository is null to trigger fallback
        jwtAlgo.setKeyRepository(null);
        
        jwtAlgo.callDeleteKeyDirectory(kv);
        
        assertFalse(Files.exists(keyDir));
    }

    @Test
    void testValidateDirectoryPath() {
        assertThrows(NullPointerException.class, () -> jwtAlgo.callValidateDirectoryPath(null));
        
        // Valid
        jwtAlgo.callValidateDirectoryPath(tempDir);
        
        // Relative path logic depends on implementation. 
        // AbstractJwtAlgo checks: !normalized.equals(path).
        // Paths.get("a/../b") is not normalized.
        assertThrows(SecurityException.class, () -> jwtAlgo.callValidateDirectoryPath(Paths.get("a/../b")));
        
        // Symbolic link
        // Need to create a symlink. 
        try {
            Path target = tempDir.resolve("target");
            Files.createDirectories(target);
            Path link = tempDir.resolve("link");
            // Windows requires admin privilege for symlinks usually, unless developer mode enabled.
            // If creation fails, we might skip or use assumeTrue.
            // But we can mock Files.isSymbolicLink using mockStatic if needed.
            // Or just trust it works on CI env.
            // Let's try mocking Files.isSymbolicLink is hard because Files is final class, need mockito-inline.
            // We have mockito-inline.
        } catch (Exception e) {
            // Ignore if symlink creation fails
        }
    }

    @Test
    void testDetectAlgorithmFromTypeDir_And_MetadataFiles() throws Exception {
        Path root = tempDir.resolve("detect");
        Files.createDirectories(root);
        // Set currentKeyPath to a child so listAllKeys() uses root as base
        jwtAlgo.setCurrentKeyPath(root.resolve("dummy"));
        
        // 1. hmac-keys
        Path hmacDir = root.resolve("hmac-keys");
        Files.createDirectories(hmacDir);
        Path v1 = hmacDir.resolve("v1");
        Files.createDirectories(v1);
        
        // 2. rsa-keys
        Path rsaDir = root.resolve("rsa-keys");
        Files.createDirectories(rsaDir);
        Path v2 = rsaDir.resolve("v2");
        Files.createDirectories(v2);
        
        // 3. ec-keys
        Path ecDir = root.resolve("ec-keys");
        Files.createDirectories(ecDir);
        Path v3 = ecDir.resolve("v3");
        Files.createDirectories(v3);
        
        // 4. eddsa-keys
        Path eddsaDir = root.resolve("eddsa-keys");
        Files.createDirectories(eddsaDir);
        Path v4 = eddsaDir.resolve("v4");
        Files.createDirectories(v4);
        
        // 5. unknown-keys
        Path unknownDir = root.resolve("unknown-keys");
        Files.createDirectories(unknownDir);
        Path v5 = unknownDir.resolve("v5");
        Files.createDirectories(v5);
        
        // Add metadata files to v1 to test readKeyExpiration and readTransitionEndTime
        Files.writeString(v1.resolve("expiration.info"), Instant.now().plusSeconds(1000).toString());
        Files.writeString(v1.resolve("transition.info"), Instant.now().plusSeconds(2000).toString());
        
        List<KeyVersion> keys = jwtAlgo.listAllKeys();
        assertEquals(5, keys.size());
        
        KeyVersion k1 = keys.stream().filter(k -> k.getKeyId().equals("v1")).findFirst().orElseThrow();
        assertEquals(Algorithm.HMAC256, k1.getAlgorithm());
        assertNotNull(k1.getExpiresAt());
        assertNotNull(k1.getTransitionEndsAt());
        
        KeyVersion k2 = keys.stream().filter(k -> k.getKeyId().equals("v2")).findFirst().orElseThrow();
        assertEquals(Algorithm.RSA256, k2.getAlgorithm());
        
        KeyVersion k3 = keys.stream().filter(k -> k.getKeyId().equals("v3")).findFirst().orElseThrow();
        assertEquals(Algorithm.ES256, k3.getAlgorithm());
        
        KeyVersion k4 = keys.stream().filter(k -> k.getKeyId().equals("v4")).findFirst().orElseThrow();
        assertEquals(Algorithm.Ed25519, k4.getAlgorithm());
        
        KeyVersion k5 = keys.stream().filter(k -> k.getKeyId().equals("v5")).findFirst().orElseThrow();
        assertEquals(Algorithm.HMAC256, k5.getAlgorithm()); // Default
    }

    @Test
    void testReadMetadata_File_Exceptions() throws Exception {
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir);
        
        Path verDir = typeDir.resolve("v1");
        Files.createDirectories(verDir);
        Files.createFile(verDir.resolve("status.info"));
        Files.createFile(verDir.resolve("expiration.info"));
        Files.createFile(verDir.resolve("transition.info"));
        Files.createFile(verDir.resolve("algorithm.info"));
        
        try (MockedStatic<Files> files = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            // Mock readString to throw IOException
            files.when(() -> Files.readString(any(Path.class), any())).thenThrow(new IOException("read error"));
            
            // Should not throw, just log and return defaults/nulls
            List<KeyVersion> keys = jwtAlgo.listAllKeys();
            assertFalse(keys.isEmpty());
            KeyVersion k = keys.get(0);
            assertEquals(KeyStatus.CREATED, k.getStatus()); // Default
            assertNull(k.getExpiresAt()); // Default null
            assertNull(k.getTransitionEndsAt()); // Default null
            assertEquals(Algorithm.HMAC256, k.getAlgorithm()); // Default from type dir
        }
    }

    @Test
    void testDeleteKeyDirectory_Recursive_Exception() throws Exception {
        Path keyDir = tempDir.resolve("hmac-keys").resolve("del-fail");
        Files.createDirectories(keyDir);
        Files.createFile(keyDir.resolve("file.txt"));
        
        KeyVersion kv = KeyVersion.builder()
                .keyId("del-fail")
                .keyPath(keyDir.toString())
                .build();
        
        jwtAlgo.setKeyRepository(null);
        
        try (MockedStatic<Files> files = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            // Mock walk to throw IOException
            files.when(() -> Files.walk(any(Path.class))).thenThrow(new IOException("walk error"));
            
            // Should throw IOException
            assertThrows(IOException.class, () -> jwtAlgo.callDeleteKeyDirectory(kv));
        }
    }

    @Test
    void testAutoLoadKey_Disk_Exception() throws Exception {
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir);
        
        Path k1 = typeDir.resolve("k1");
        Files.createDirectories(k1);
        
        try (MockedStatic<Files> files = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            // Mock exists(candidate) to throw
            // candidate = currentKeyPath.resolve(preferredKeyId)
            // But we need to be careful not to break other checks.
            // AbstractJwtAlgo.autoLoadKey:
            // Path candidate = currentKeyPath.resolve(preferredKeyId);
            // if (Files.exists(candidate) && Files.isDirectory(candidate))
            
            files.when(() -> Files.exists(eq(k1))).thenThrow(new RuntimeException("disk error"));
            
            // Should return this (fail gracefully)
            JwtAlgo res = jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, "k1", false);
            assertNotNull(res);
            assertNull(jwtAlgo.getActiveKeyId());
        }
    }

    @Test
    void testListAllKeys_MalformedDirName() throws Exception {
        Path typeDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(typeDir);
        jwtAlgo.setCurrentKeyPath(typeDir);
        
        Path verDir = typeDir.resolve("bad-name");
        Files.createDirectories(verDir);
        
        List<KeyVersion> keys = jwtAlgo.listAllKeys();
        assertFalse(keys.isEmpty());
        KeyVersion k = keys.get(0);
        // Created time should be fallback (yesterday)
        assertTrue(k.getCreatedTime().isBefore(LocalDateTime.now().minusHours(23)));
    }

    @Test
    void testValidateDirectoryPath_Normalization() {
        // Mock Files.exists to avoid actual file system checks if possible, or just use tempDir
        // Path "tempDir/a/../b" should normalize to "tempDir/b"
        // But AbstractJwtAlgo checks: if (!normalized.equals(path))
        // So if we pass non-normalized path, it should throw.
        
        Path nonNorm = tempDir.resolve("a").resolve("..").resolve("b");
        assertThrows(SecurityException.class, () -> jwtAlgo.callValidateDirectoryPath(nonNorm));
    }

    @Test
    void testValidateDirectoryPath_Symlink() {
        // Mock Files.isSymbolicLink
        try (MockedStatic<Files> files = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            files.when(() -> Files.isSymbolicLink(any(Path.class))).thenReturn(true);
            
            assertThrows(SecurityException.class, () -> jwtAlgo.callValidateDirectoryPath(tempDir));
        }
    }

    // --- Helper Classes ---

    static class TestClaims {
        public String foo;
        public TestClaims() {}
        public TestClaims(String foo) { this.foo = foo; }
    }

    /**
     * Concrete implementation of AbstractJwtAlgo for testing.
     */
    static class TestJwtAlgo extends AbstractJwtAlgo {
        private volatile boolean failLoadKeyPair;
        private final Map<String, KeyVersion> keysOnDisk = new HashMap<>();

        public TestJwtAlgo(KeyMinterProperties properties, Path tempDir) {
            super(properties);
            this.currentKeyPath = tempDir;
        }
        
        public void setKeyToLoadOnDisk(String keyId, KeyVersion version) {
            keysOnDisk.put(keyId, version);
        }

        // Expose protected method for testing
        public void setActiveKeyIdDirectly(String keyId) {
            this.activeKeyId = keyId;
        }

        public void addKeyVersion(KeyVersion version) {
            this.keyVersions.put(version.getKeyId(), version);
        }

        public void setLoadKeyPairFailure(boolean fail) {
            this.failLoadKeyPair = fail;
        }

        public void setCurrentKeyPath(Path path) {
            this.currentKeyPath = path;
        }

        public void setKeyRepository(KeyRepository repo) {
            this.keyRepository = repo;
        }

        public Optional<Path> callFindKeyDir(String tag, java.util.function.Predicate<Path> extraFilter) {
            return super.findKeyDir(tag, extraFilter);
        }

        public void callUpdateKeyStatusFile(String keyId, KeyStatus status) {
            super.updateKeyStatusFile(keyId, status);
        }

        public void callMarkKeyActive(String keyId) {
            super.markKeyActive(keyId);
        }

        public void callValidateHmacAlgorithm(Algorithm algorithm) {
            super.validateHmacAlgorithm(algorithm);
        }

        public void callValidateRsaAlgorithm(Algorithm algorithm) {
            super.validateRsaAlgorithm(algorithm);
        }

        public void callValidateEcdsaAlgorithm(Algorithm algorithm) {
            super.validateEcdsaAlgorithm(algorithm);
        }

        public void callValidateEddsaAlgorithm(Algorithm algorithm) {
            super.validateEddsaAlgorithm(algorithm);
        }

        public boolean callCanKeyVerify(String keyId) {
            return super.canKeyVerify(keyId);
        }

        public boolean callCanKeyNotVerify(String keyId) {
            return super.canKeyNotVerify(keyId);
        }

        public JwtBuilder callCreateJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
            return super.createJwtBuilder(properties, customClaims);
        }

        public void callDeleteKeyDirectory(KeyVersion version) throws java.io.IOException {
            super.deleteKeyDirectory(version);
        }

        public void callValidateDirectoryPath(Path path) {
            super.validateDirectoryPath(path);
        }

        @Override
        protected void loadKeyPair(String keyId) {
            if (failLoadKeyPair) {
                throw new RuntimeException("load failed");
            }
            super.loadKeyPair(keyId);
        }

        @Override
        public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
            return "dummy-token";
        }

        @Override
        public boolean verifyToken(String token) {
            return true;
        }

        @Override
        public boolean verifyWithKeyVersion(String keyVersionId, String token) {
            return true;
        }

        @Override
        public Claims decodePayload(String token) {
            return null;
        }

        @Override
        public boolean generateKeyPair(Algorithm algorithm) {
            return false;
        }

        @Override
        public boolean generateHmacKey(Algorithm algorithm, Integer length) {
            return false;
        }

        @Override
        public boolean generateAllKeyPairs() {
            return false;
        }

        @Override
        public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
            return false;
        }

        @Override
        public boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
            return false;
        }

        @Override
        public List<KeyVersion> listKeys(Algorithm algorithm) {
            return List.of();
        }

        @Override
        public void loadExistingKeyVersions() {
        }

        @Override
        public Object getCurrentKey() {
            return null;
        }

        @Override
        public Object getKeyByVersion(String keyId) {
            return null;
        }

        @Override
        public String getCurveInfo(Algorithm algorithm) {
            return "";
        }

        @Override
        protected boolean hasKeyFilesInDirectory(String tag) {
            return false;
        }

        @Override
        protected void loadFirstKeyFromDirectory(String tag) {
            // No-op
        }

        @Override
        protected void loadKeyVersion(Path path) {
            String keyId = path.getFileName().toString();
            if (keysOnDisk.containsKey(keyId)) {
                this.keyVersions.put(keyId, keysOnDisk.get(keyId));
            }
        }

        @Override
        protected boolean isKeyVersionDir(Path dir) {
            return false;
        }

        @Override
        protected Object getSignAlgorithm(Algorithm algorithm) {
            return null;
        }
    }
}



