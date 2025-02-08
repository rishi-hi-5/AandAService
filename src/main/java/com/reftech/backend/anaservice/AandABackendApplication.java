package com.reftech.backend.anaservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration;
import reactor.core.publisher.Hooks;

@SpringBootApplication(exclude = {RedisReactiveAutoConfiguration.class})
public class AandABackendApplication {
    public static void main(String[] args) {

        Hooks.onOperatorDebug();
        SpringApplication.run(AandABackendApplication.class, args);
    }
}
