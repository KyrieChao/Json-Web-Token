package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Constructor;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class EddsaJwtExtendedTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    private EddsaJwt eddsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        when(properties.getKeyValidityMillis()).thenReturn(3600000L);
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        
        eddsaJwt = new EddsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (eddsaJwt != null) {
            eddsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testEd448Signing() {
        // This should trigger CustomEd448Signer
        eddsaJwt.generateKeyPair(Algorithm.Ed448);
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed448);
        String keyId = keys.get(0);
        eddsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties("sub", "iss", Instant.now().plusSeconds(60));
        String token = eddsaJwt.generateJwt(jwtProps, null, Algorithm.Ed448);
        
        assertNotNull(token);
        assertTrue(eddsaJwt.verifyToken(token));
    }
    
    @Test
    void testGetCurveInfo() {
        eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed25519);
        eddsaJwt.setActiveKey(keys.get(0));
        
        String info = eddsaJwt.getCurveInfo(Algorithm.Ed25519);
        assertTrue(info.contains("Ed25519"));
        
        // Ed448
        eddsaJwt.generateKeyPair(Algorithm.Ed448);
        List<String> keys448 = eddsaJwt.getKeyVersions(Algorithm.Ed448);
        eddsaJwt.setActiveKey(keys448.get(0));
        
        String info448 = eddsaJwt.getCurveInfo(Algorithm.Ed448);
        assertTrue(info448.contains("Ed448"));
    }
    
    @Test
    void testConstructors() {
        EddsaJwt defaultJwt = null;
        try {
            defaultJwt = new EddsaJwt();
            assertNotNull(defaultJwt);
        } catch (Exception e) {
            // ignore
        } finally {
            if (defaultJwt != null) defaultJwt.close();
        }
        
        EddsaJwt pathJwt = null;
        try {
            pathJwt = new EddsaJwt(tempDir);
            assertNotNull(pathJwt);
        } finally {
            if (pathJwt != null) pathJwt.close();
        }
    }
    
    @Test
    void testGenerateAllKeyPairs() {
        assertTrue(eddsaJwt.generateAllKeyPairs());
        assertTrue(eddsaJwt.getKeyVersions(Algorithm.Ed25519).size() > 0);
        assertTrue(eddsaJwt.getKeyVersions(Algorithm.Ed448).size() > 0);
    }
    
    @Test
    void testGetKeyInfo() {
        String info = eddsaJwt.getKeyInfo();
        assertTrue(info.contains("EdDSA Keys"));
    }
    
    @Test
    void testAlgorithmInfo() {
        String info = eddsaJwt.getAlgorithmInfo();
        assertTrue(info.contains("Ed25519"));
    }
}
