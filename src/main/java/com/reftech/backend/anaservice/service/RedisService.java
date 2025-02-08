package com.reftech.backend.anaservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import java.time.Duration;

@Service
@Slf4j
public class RedisService {



    @Autowired
    @Qualifier("reactiveRedisTemplate")
    private ReactiveRedisTemplate<String, String> redisReactiveTemplate;

    /**
     * Saves a key-value pair in Redis with an optional expiration time.
     */
    public Mono<String> save(String key, String value, Duration duration) {
        return redisReactiveTemplate.opsForValue()
                .set(key, value, duration)
                .doOnSuccess(success -> log.info("Saved key: {}, value: {}, duration: {}", key, value, duration))
                .thenReturn(value);
    }

    /**
     * Retrieves a value from Redis based on the key.
     */
    public Mono<String> get(String key) {
        return redisReactiveTemplate.opsForValue()
                .get(key)
                .doOnNext(value -> log.info("Retrieved key: {}, value: {}", key, value))
                .switchIfEmpty(Mono.just("")); // Ensures Mono completes even if key is absent
    }

    /**
     * Deletes a key from Redis.
     */
    public Mono<Boolean> delete(String key) {
        return redisReactiveTemplate.opsForValue()
                .delete(key)
                .doOnSuccess(deleted -> log.info("Deleted key: {}, success: {}", key, deleted));
    }
}