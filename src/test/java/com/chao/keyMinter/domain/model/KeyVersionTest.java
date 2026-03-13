package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class KeyVersionTest {
    LocalDateTime fixed = LocalDateTime.of(2026, 3, 13, 21, 38, 0);

    @Test
    void canVerify() {
        KeyVersion kv = new KeyVersion();
        kv.setKeyId("keyId");
        kv.setTransitionEndsAt(Instant.ofEpochMilli(1));
        kv.setStatus(KeyStatus.INACTIVE);
        assertFalse(kv.canVerify());
    }

    @Test
    void isInTransitionPeriod() {
        KeyVersion kv = new KeyVersion();
        kv.setStatus(KeyStatus.TRANSITIONING);
        assertTrue(kv.isInTransitionPeriod());

        KeyVersion kv2 = new KeyVersion();
        kv2.setStatus(KeyStatus.INACTIVE);
        kv2.setTransitionEndsAt(Instant.now().plusMillis(10_000));
        assertTrue(kv2.isInTransitionPeriod());

        KeyVersion kv3 = new KeyVersion();
        kv3.setStatus(KeyStatus.EXPIRED);
        kv3.setTransitionEndsAt(Instant.now().plusMillis(10_000));
        assertFalse(kv3.isInTransitionPeriod());

        KeyVersion kv4 = new KeyVersion();
        kv4.setStatus(KeyStatus.ACTIVE);
        kv4.setTransitionEndsAt(Instant.now());
        assertFalse(kv4.isInTransitionPeriod());
    }

    @Test
    void isExpired() {
        // 未设置过期时间 = 永不过期
        KeyVersion kv = new KeyVersion();
        kv.setExpiresAt(null);
        assertFalse(kv.isExpired());

        // 未来10秒 = 未过期
        Instant now = Instant.now();

        KeyVersion kv2 = new KeyVersion();
        kv2.setExpiresAt(now.plusSeconds(3600)); // 1小时后过期
        assertFalse(kv2.isExpired());

        KeyVersion kv3 = new KeyVersion();
        kv3.setExpiresAt(now.minusSeconds(3600)); // 1小时前过期
        assertTrue(kv3.isExpired());

        // 刚好现在 = 未过期（isAfter是严格大于）
        KeyVersion kv4 = new KeyVersion();
        kv4.setExpiresAt(Instant.now());
        assertFalse(kv4.isExpired());
    }

    @Test
    void getRemainingSeconds() {
        KeyVersion kv = new KeyVersion();
        kv.setExpiresAt(null);
        assertEquals(Long.MAX_VALUE, kv.getRemainingSeconds());

        KeyVersion kv2 = new KeyVersion();
        kv2.setExpiresAt(Instant.now().plusSeconds(10));
        assertEquals(10, kv2.getRemainingSeconds());

        KeyVersion kv3 = new KeyVersion();
        kv3.setExpiresAt(Instant.now().minusMillis(10_000));
        assertEquals(0, kv3.getRemainingSeconds());
    }

    @Test
    void setExpiresAt() {
        KeyVersion kv = new KeyVersion();
        Instant fixedExpire = Instant.parse("2026-03-13T13:33:46.304387619Z");
        kv.setExpiresAt(fixedExpire);
        assertEquals(fixedExpire, kv.getExpiresAt());
    }

    @Test
    void createdTime() {
        KeyVersion kv = new KeyVersion();
        kv.setCreatedTime(fixed);
        assertEquals(fixed, kv.getCreatedTime());
    }

}