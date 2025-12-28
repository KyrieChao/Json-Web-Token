package key_minter.config;

import key_minter.model.Algorithm;

public interface KeyMinterOverrides {
    Algorithm algorithm();
    String preferredKeyId();
}
