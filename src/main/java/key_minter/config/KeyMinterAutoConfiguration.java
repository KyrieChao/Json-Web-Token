package key_minter.config;

import key_minter.auth.core.Jwt;
import key_minter.model.Algorithm;
import key_minter.auth.factory.JwtFactory;
import key_minter.util.KeyMinter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.nio.file.Paths;

@AutoConfiguration
@EnableConfigurationProperties({KeyMinterProperties.class, CleanArchProperties.class})
@ConditionalOnClass({JwtFactory.class, Algorithm.class})
public class KeyMinterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(KeyMinterOverrides.class)
    public KeyMinterOverrides keyMinterOverrides(KeyMinterProperties properties) {
        return new PropertiesKeyMinterOverrides(properties);
    }

    @Bean
    public Jwt keyMinterJwt(KeyMinterProperties properties, KeyMinterOverrides overrides,ObjectProvider<List<KeyMinterConfigurer>> configurersProvider) {
        if (properties.getBaseDir() != null && !properties.getBaseDir().isBlank()) {
            SecretDirProvider.setDefaultBaseDir(Paths.get(properties.getBaseDir()));
        } else if (properties.getKeyDir() != null && !properties.getKeyDir().isBlank()) {
            SecretDirProvider.setDefaultBaseDir(Paths.get(properties.getKeyDir()));
        }
        KeyMinterBuilder builder = new KeyMinterBuilder()
                .setAlgorithm(overrides.algorithm() != null ? overrides.algorithm() : properties.getAlgorithm())
                .setPreferredKeyId(overrides.preferredKeyId() != null ? overrides.preferredKeyId() : properties.getPreferredKeyId());

        List<KeyMinterConfigurer> configurers = configurersProvider.getIfAvailable();
        if (configurers != null) {
            for (KeyMinterConfigurer configurer : configurers) {
                configurer.configure(builder);
            }
        }

        Algorithm algorithm = builder.getAlgorithm() != null ? builder.getAlgorithm() : Algorithm.HMAC256;
        String preferredKeyId = builder.getPreferredKeyId();
        String directory = properties.getKeyDir();

        return JwtFactory.autoLoad(algorithm, directory, preferredKeyId,
                properties.isEnableRotation(), properties.isForceLoad());
    }

    @Bean
    @ConditionalOnMissingBean(KeyMinter.class)
    public KeyMinter keyMinterBean() {
        return new KeyMinter();
    }
}
