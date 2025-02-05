package com.reftech.backend.anaservice.service;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static com.reftech.backend.anaservice.model.Constants.BLACKLIST_DURATION;
import static com.reftech.backend.anaservice.model.Constants.BLACKLIST_PREFIX;

@Component
@Slf4j
public class TokenBlackListService {
    @Autowired
    RedisService redisService;

    public Mono<Void> blackList(String token) {
        String key = BLACKLIST_PREFIX + token;
        return redisService.save(key, token, Duration.ofMinutes(BLACKLIST_DURATION))
                .then();
    }
    public Mono<Boolean> isBlackListed(String token) {
        return redisService
                .get(BLACKLIST_PREFIX + token)
                .doOnNext(value -> log.info("Token value from Redis: {}", value))
                .map(value -> true) // If found in Redis, it's blacklisted
                .defaultIfEmpty(false) // If Redis returns nothing, it's not blacklisted
                .doOnTerminate(() -> log.info("Blacklist check completed"));
    }
}
