package key_minter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("key-minter.clean-arch")
public class CleanArchProperties {
    private boolean enabled = false;

    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

