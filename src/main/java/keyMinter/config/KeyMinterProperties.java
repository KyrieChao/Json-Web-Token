package keyMinter.config;

import keyMinter.model.Algorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("key-minter")
public class KeyMinterProperties {
    private Algorithm algorithm;
    private String keyDir;
    private boolean enableRotation;
    private String preferredKeyId;
    private boolean forceLoad;
    private Integer maxAlgoInstance;
    private boolean exportEnabled;
    private boolean metricsEnabled;
    private final Blacklist blacklist = new Blacklist();
    private final Lock lock = new Lock();

    @Data
    public static class Blacklist {
        private boolean redisEnabled = false;
        private String redisKeyPrefix = "keyM:black:";
        private int redisBatchSize = 1000;
    }

    @Data
    public static class Lock {
        private boolean redisEnabled = false;
        private String redisKeyPrefix = "keyM:lock:";
        private long expireMillis = 30000;
        private long retryIntervalMillis = 100;
        private long maxRetryIntervalMillis = 2000;
    }
}
