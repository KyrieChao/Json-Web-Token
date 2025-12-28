package key_minter.presentation;

import key_minter.application.usecase.TokenUseCase;
import key_minter.model.Algorithm;
import key_minter.model.JwtProperties;

/**
 * @since 2025
 * Presentation facade for new clean-arch pipeline (placeholder).
 */
public class KeyMinterApi {
    private final TokenUseCase tokenUseCase;

    public KeyMinterApi(TokenUseCase tokenUseCase) {
        this.tokenUseCase = tokenUseCase;
    }

    public String generate(JwtProperties props, Algorithm algorithm) {
        return tokenUseCase.generate(props, algorithm);
    }
}
