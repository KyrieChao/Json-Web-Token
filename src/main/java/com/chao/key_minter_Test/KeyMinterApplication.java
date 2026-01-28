package com.chao.key_minter_Test;

import keyMinter.config.KeyMinterAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(KeyMinterAutoConfiguration.class)
public class KeyMinterApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeyMinterApplication.class, args);
    }

}
