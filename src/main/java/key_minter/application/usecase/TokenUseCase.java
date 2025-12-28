package key_minter.application.usecase;

import key_minter.domain.ports.KmsPort;
import key_minter.domain.ports.KeyStorePort;
import key_minter.model.Algorithm;
import key_minter.model.JwtProperties;

/**
 * @since 2025
 * Application use case orchestrating token generation/verification via domain ports.
 */
public class TokenUseCase {
    private final KmsPort kms;
    private final KeyStorePort store;

    public TokenUseCase(KmsPort kms, KeyStorePort store) {
        this.kms = kms;
        this.store = store;
    }

    public String generate(JwtProperties props, Algorithm algorithm) {
        // Placeholder: the concrete generation remains in legacy path until migrated
        return null;
    }

    public boolean verify(String token, Algorithm algorithm) {
        return false;
    }
}
