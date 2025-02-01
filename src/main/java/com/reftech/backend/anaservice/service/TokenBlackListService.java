package com.reftech.backend.anaservice.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static com.reftech.backend.anaservice.model.Constants.BLACKLIST_DURATION;
import static com.reftech.backend.anaservice.model.Constants.BLACKLIST_PREFIX;

@Component
public class TokenBlackListService {
    @Autowired
    RedisService redisService;

    public Mono<Void> blackList(String token) {
        String key = BLACKLIST_PREFIX + token;
        return redisService.save(key, token, Duration.ofMinutes(BLACKLIST_DURATION))
                .then();
    }

    public Mono<Boolean> isBlackListed(String token) {
        String key = BLACKLIST_PREFIX + token;
        return redisService.get(key)
                .flatMap(value-> Mono.just(value!=null));
    }
}
