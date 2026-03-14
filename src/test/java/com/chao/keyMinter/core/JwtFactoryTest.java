package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.service.JwtAlgo;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import org.junit.jupiter.api.AfterEach;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtFactoryTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepositoryFactory repositoryFactory;

    private JwtFactory jwtFactory;
    private AutoCloseable mocks;
    private Path originalBaseDir;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        // Mock default base dir to temp dir
        originalBaseDir = SecretDirProvider.getDefaultBaseDir();
        SecretDirProvider.setDefaultBaseDir(tempDir);
        
        jwtFactory = new JwtFactory();
        
        // Mock properties behavior
        lenient().when(properties.getKeyDir()).thenReturn(tempDir.toString());
        lenient().when(properties.getMaxAlgoInstance()).thenReturn(5);
        
        jwtFactory.setProperties(properties);
        jwtFactory.setRepositoryFactory(repositoryFactory);
    }

    @AfterEach
    void tearDown() throws Exception {
        jwtFactory.close();
        if (mocks != null) {
            mocks.close();
        }
        if (originalBaseDir != null) {
            SecretDirProvider.setDefaultBaseDir(originalBaseDir);
        }
    }

    @Test
    void testGetDefault() {
        JwtAlgo algo = jwtFactory.get();
        assertNotNull(algo);
        assertTrue(algo instanceof HmacJwt);
        assertEquals(1, jwtFactory.getCacheSize());
    }

    @Test
    void testGetWithAlgorithm() {
        JwtAlgo algo = jwtFactory.get(Algorithm.RSA256);
        assertNotNull(algo);
        assertTrue(algo instanceof RsaJwt);
    }

    @Test
    void testGetWithAlgorithmAndPath() {
        // Unset repository factory to ensure we use path-based initialization
        jwtFactory.setRepositoryFactory(null);
        
        JwtAlgo algo = jwtFactory.get(Algorithm.HMAC256, tempDir);
        assertNotNull(algo);
        // Normalize paths for comparison
        Path expected = tempDir.resolve("hmac-keys").toAbsolutePath().normalize();
        Path actual = algo.getKeyPath().toAbsolutePath().normalize();
        assertEquals(expected, actual);
    }

    @Test
    void testCaching() {
        JwtAlgo algo1 = jwtFactory.get(Algorithm.HMAC256, tempDir);
        JwtAlgo algo2 = jwtFactory.get(Algorithm.HMAC256, tempDir);
        
        assertSame(algo1, algo2);
        assertEquals(1, jwtFactory.getCacheSize());
    }

    @Test
    void testDifferentPathsCreateDifferentInstances() {
        JwtAlgo algo1 = jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("dir1"));
        JwtAlgo algo2 = jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("dir2"));
        
        assertNotSame(algo1, algo2);
        assertEquals(2, jwtFactory.getCacheSize());
    }

    @Test
    void testEviction() {
        // Set small max size via properties mock is not enough because it's read on init
        // We need to trigger the cache logic.
        // Since maxAlgoInstance is volatile and set in setProperties, we can try to re-set it?
        // But the cache is initialized in constructor.
        // Wait, the cache implementation reads maxAlgoInstance dynamically in removeEldestEntry?
        // No, `maxAlgoInstance` is a field in JwtFactory. The cache is an anonymous inner class 
        // that captures `this` (implicitly) or accesses the field.
        // Yes, `if (size() > maxAlgoInstance)` inside `removeEldestEntry`.
        
        when(properties.getMaxAlgoInstance()).thenReturn(2);
        jwtFactory.setProperties(properties); // Update max size
        
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("1"));
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("2"));
        assertEquals(2, jwtFactory.getCacheSize());
        
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("3"));
        assertEquals(2, jwtFactory.getCacheSize()); // Should have evicted one
    }

    @Test
    void testAutoLoad() {
        JwtAlgo algo = jwtFactory.autoLoad(Algorithm.HMAC256, tempDir);
        assertNotNull(algo);
        // Since tempDir is empty, it won't load anything, but it should return the algo instance
    }
    
    @Test
    void testAutoLoadOverloads() {
        // 1. autoLoad(Algorithm)
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256));

        // 2. autoLoad(Algorithm, boolean)
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, true));

        // 3. autoLoad(Algorithm, String)
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, tempDir.toString()));
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, (String) null));

        // 4. autoLoad(Algorithm, String, String)
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, tempDir.toString(), "k1"));
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, (String) null, "k1"));

        // 5. autoLoad(Algorithm, String, String, boolean)
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, tempDir.toString(), "k1", true));
        assertNotNull(jwtFactory.autoLoad(Algorithm.HMAC256, (String) null, "k1", true));
    }

    @Test
    void testResolveKeyDirFallback() {
        JwtFactory factory = new JwtFactory();
        // Case 1: Properties is null
        factory.setProperties(null);
        // Should resolve to default base dir and print to System.out (not checking output here, just coverage)
        assertNotNull(factory.get(Algorithm.HMAC256, (Path) null));

        // Case 2: Properties keyDir is null
        KeyMinterProperties props = mock(KeyMinterProperties.class);
        when(props.getKeyDir()).thenReturn(null);
        factory.setProperties(props);
        assertNotNull(factory.get(Algorithm.HMAC256, (Path) null));

        // Case 3: Properties keyDir is empty
        when(props.getKeyDir()).thenReturn("");
        assertNotNull(factory.get(Algorithm.HMAC256, (Path) null));
    }

    @Test
    void testEvictionWithException() throws Exception {
        // Setup a factory with size 1
        JwtFactory factory = new JwtFactory();
        KeyMinterProperties props = mock(KeyMinterProperties.class);
        when(props.getMaxAlgoInstance()).thenReturn(1);
        factory.setProperties(props);

        // Inject a mock Algo that throws on close
        JwtAlgo mockAlgo = mock(JwtAlgo.class);
        doThrow(new RuntimeException("close error")).when(mockAlgo).close();

        // Use reflection to insert into cache (since get() creates real ones)
        // Or we can just spy on the factory? No, build() is private.
        // We can use reflection to access the cache map.
        java.lang.reflect.Field cacheField = JwtFactory.class.getDeclaredField("cache");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Map<String, JwtAlgo> cache = (java.util.Map<String, JwtAlgo>) cacheField.get(factory);

        // Put mock algo
        cache.put("MOCK:KEY", mockAlgo);

        // Trigger eviction by adding another
        factory.get(Algorithm.HMAC256, tempDir.resolve("new"));

        // Verify close was called (exception swallowed logged)
        verify(mockAlgo).close();
        assertEquals(1, factory.getCacheSize());
    }

    @Test
    void testClearCacheWithException() throws Exception {
        // Setup a factory
        JwtFactory factory = new JwtFactory();
        
        // Inject a mock Algo that throws on close
        JwtAlgo mockAlgo = mock(JwtAlgo.class);
        doThrow(new RuntimeException("close error")).when(mockAlgo).close();

        java.lang.reflect.Field cacheField = JwtFactory.class.getDeclaredField("cache");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Map<String, JwtAlgo> cache = (java.util.Map<String, JwtAlgo>) cacheField.get(factory);

        cache.put("MOCK:KEY", mockAlgo);

        // Clear cache
        factory.clearCache();

        // Verify close was called
        verify(mockAlgo).close();
        assertEquals(0, factory.getCacheSize());
    }
}



