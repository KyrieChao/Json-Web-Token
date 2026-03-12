package com.chao.keyminter.adapter.in;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeyMinterPropertiesTest {

    @Test
    void testDefaultValues() {
        // Arrange
        KeyMinterProperties properties = new KeyMinterProperties();

        // Act & Assert
        assertEquals(System.getProperty("user.home") + "/.keyminter", properties.getKeyDir(), "Default key directory should be user home .keyminter");
        assertFalse(properties.isEnableRotation(), "Rotation should be disabled by default");
        assertEquals(90, properties.getKeyValidityDays(), "Default validity should be 90 days");
        assertEquals(24, properties.getTransitionPeriodHours(), "Default transition period should be 24 hours");
        assertEquals(7, properties.getRotationAdvanceDays(), "Default rotation advance should be 7 days");
        assertEquals(60, properties.getBlacklistCleanupIntervalMinutes(), "Default blacklist cleanup should be 60 minutes");
        assertEquals(24, properties.getBlacklistEntryTtlHours(), "Default blacklist TTL should be 24 hours");
        assertEquals(24, properties.getExpiredKeyCleanupIntervalHours(), "Default expired key cleanup should be 24 hours");
        assertEquals(30L * 24 * 60 * 60 * 1000, properties.getExpiredKeyRetentionMillis(), "Default retention should be 30 days in millis");
        
        assertNotNull(properties.getBlacklist(), "Blacklist config object should not be null");
        assertNotNull(properties.getLock(), "Lock config object should not be null");
    }

    @Test
    void testLombokMethods() {
        KeyMinterProperties p1 = new KeyMinterProperties();
        p1.setKeyDir("dir1");
        
        KeyMinterProperties p2 = new KeyMinterProperties();
        p2.setKeyDir("dir1");
        
        KeyMinterProperties p3 = new KeyMinterProperties();
        p3.setKeyDir("dir2");
        
        // Equals
        assertEquals(p1, p2);
        assertNotEquals(p1, p3);
        assertNotEquals(p1, null);
        assertNotEquals(p1, new Object());
        
        // HashCode
        assertEquals(p1.hashCode(), p2.hashCode());
        assertNotEquals(p1.hashCode(), p3.hashCode());
        
        // ToString
        assertNotNull(p1.toString());
        assertTrue(p1.toString().contains("dir1"));
        
        // Nested classes
        KeyMinterProperties.Blacklist b1 = new KeyMinterProperties.Blacklist();
        b1.setRedisEnabled(true);
        KeyMinterProperties.Blacklist b2 = new KeyMinterProperties.Blacklist();
        b2.setRedisEnabled(true);
        assertEquals(b1, b2);
        assertEquals(b1.hashCode(), b2.hashCode());
        assertNotNull(b1.toString());
        
        KeyMinterProperties.Lock l1 = new KeyMinterProperties.Lock();
        l1.setRedisEnabled(true);
        KeyMinterProperties.Lock l2 = new KeyMinterProperties.Lock();
        l2.setRedisEnabled(true);
        assertEquals(l1, l2);
        assertEquals(l1.hashCode(), l2.hashCode());
        assertNotNull(l1.toString());
    }

    @Test
    void testCalculatedProperties() {
        // Arrange
        KeyMinterProperties properties = new KeyMinterProperties();
        properties.setKeyValidityDays(1);
        properties.setTransitionPeriodHours(1);
        properties.setRotationAdvanceDays(1);
        properties.setBlacklistCleanupIntervalMinutes(1);
        properties.setBlacklistEntryTtlHours(1);
        properties.setExpiredKeyCleanupIntervalHours(1);

        // Act & Assert
        assertEquals(24 * 60 * 60 * 1000L, properties.getKeyValidityMillis(), "1 day should be converted to correct millis");
        assertEquals(60 * 60 * 1000L, properties.getTransitionPeriodMillis(), "1 hour should be converted to correct millis");
        assertEquals(24 * 60 * 60 * 1000L, properties.getRotationAdvanceMillis(), "1 day advance should be converted to correct millis");
        assertEquals(60 * 1000L, properties.getBlacklistCleanupIntervalMillis(), "1 minute cleanup should be converted to correct millis");
        assertEquals(60 * 60 * 1000L, properties.getBlacklistEntryTtlMillis(), "1 hour TTL should be converted to correct millis");
        assertEquals(60 * 60 * 1000L, properties.getExpiredKeyCleanupIntervalMillis(), "1 hour expired cleanup should be converted to correct millis");
    }

    @Test
    void testNestedProperties() {
        // Arrange
        KeyMinterProperties properties = new KeyMinterProperties();
        KeyMinterProperties.Blacklist blacklist = properties.getBlacklist();
        KeyMinterProperties.Lock lock = properties.getLock();

        // Act
        blacklist.setRedisEnabled(true);
        blacklist.setRedisKeyPrefix("test:black:");
        blacklist.setRedisBatchSize(500);

        lock.setRedisEnabled(true);
        lock.setRedisKeyPrefix("test:lock:");
        lock.setExpireMillis(1000);
        lock.setRetryIntervalMillis(50);
        lock.setMaxRetryIntervalMillis(500);

        // Assert
        assertTrue(properties.getBlacklist().isRedisEnabled());
        assertEquals("test:black:", properties.getBlacklist().getRedisKeyPrefix());
        assertEquals(500, properties.getBlacklist().getRedisBatchSize());

        assertTrue(properties.getLock().isRedisEnabled());
        assertEquals("test:lock:", properties.getLock().getRedisKeyPrefix());
        assertEquals(1000, properties.getLock().getExpireMillis());
        assertEquals(50, properties.getLock().getRetryIntervalMillis());
        assertEquals(500, properties.getLock().getMaxRetryIntervalMillis());
    }
    
    @Test
    void testSetters() {
        // Arrange
        KeyMinterProperties properties = new KeyMinterProperties();
        
        // Act
        properties.setAlgorithm(com.chao.keyminter.domain.model.Algorithm.HMAC256);
        properties.setKeyDir("/tmp/keys");
        properties.setEnableRotation(true);
        properties.setPreferredKeyId("key-123");
        properties.setForceLoad(true);
        properties.setExportEnabled(true);
        properties.setMetricsEnabled(true);
        properties.setMaxAlgoInstance(10);
        properties.setAutoCleanupExpiredKeys(true);
        
        // Assert
        assertEquals(com.chao.keyminter.domain.model.Algorithm.HMAC256, properties.getAlgorithm());
        assertEquals("/tmp/keys", properties.getKeyDir());
        assertTrue(properties.isEnableRotation());
        assertEquals("key-123", properties.getPreferredKeyId());
        assertTrue(properties.isForceLoad());
        assertTrue(properties.isExportEnabled());
        assertTrue(properties.isMetricsEnabled());
        assertEquals(10, properties.getMaxAlgoInstance());
        assertTrue(properties.isAutoCleanupExpiredKeys());
    }
}
