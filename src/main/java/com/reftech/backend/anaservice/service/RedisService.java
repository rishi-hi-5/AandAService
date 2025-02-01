package com.reftech.backend.anaservice.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
public class RedisService {

    @Autowired
    ReactiveRedisTemplate<String, String> redisReactiveTemplate;

    public Mono<String> save(String key, String value, Duration duration) {
        return redisReactiveTemplate
                .opsForValue()
                .set(key, value,duration)
                .thenReturn(value);
    }

    public Mono<String> get(String key) {
        return redisReactiveTemplate
                .opsForValue()
                .get(key);
    }
}
