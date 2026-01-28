package keyMinter.config;

import keyMinter.api.KeyMinter;
import keyMinter.internal.core.JwtFactory;
import keyMinter.internal.rotation.KeyRotation;
import keyMinter.model.Algorithm;
import keyMinter.spi.support.RedisLockProvider;
import keyMinter.spi.support.RevocationStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties({KeyMinterProperties.class})
@ConditionalOnClass({JwtFactory.class, Algorithm.class})
public class KeyMinterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtFactory.class)
    public JwtFactory jwtFactory(KeyMinterProperties properties) {
        JwtFactory factory = new JwtFactory();
        factory.setProperties(properties);
        return factory;
    }

    @Bean
    @ConditionalOnMissingBean(KeyMinter.class)
    public KeyMinter keyMinterBean(JwtFactory jwtFactory) {
        return new KeyMinter(jwtFactory);
    }

    @Bean
    @ConditionalOnProperty(prefix = "key-minter.lock", name = "redis-enabled", havingValue = "true")
    @ConditionalOnMissingBean(keyMinter.spi.LockProvider.class)
    @ConditionalOnClass(StringRedisTemplate.class)
    public keyMinter.spi.LockProvider redisLockProvider(StringRedisTemplate redisTemplate, KeyMinterProperties properties) {
        KeyMinterProperties.Lock lockProps = properties.getLock();
        RedisLockProvider provider = new RedisLockProvider(
                redisTemplate,
                lockProps.getRedisKeyPrefix(),
                lockProps.getExpireMillis(),
                lockProps.getRetryIntervalMillis(),
                lockProps.getMaxRetryIntervalMillis()
        );
        // 静态注入到工具类（因为 AtomicKeyRotation 目前是工具类设计）
        KeyRotation.setLockProvider(provider);
        return provider;
    }

    @Bean
    @ConditionalOnProperty(prefix = "key-minter.blacklist", name = "redis-enabled", havingValue = "true")
    @ConditionalOnMissingBean(keyMinter.spi.RevocationStore.class)
    @ConditionalOnClass(StringRedisTemplate.class)
    public keyMinter.spi.RevocationStore redisRevocationStore(StringRedisTemplate redisTemplate, KeyMinterProperties properties) {
        return new RevocationStore(redisTemplate, properties.getBlacklist().getRedisKeyPrefix());
    }
}
