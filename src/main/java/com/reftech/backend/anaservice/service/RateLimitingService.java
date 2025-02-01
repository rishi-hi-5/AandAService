package com.reftech.backend.anaservice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.reftech.backend.anaservice.model.Constants.*;
import static com.reftech.backend.anaservice.utility.StringIntegerUtility.incrementValue;

@Component
public class RateLimitingService {
    @Autowired
    private RedisService redisService;

    private static final Predicate<String> IS_RATE_LIMIT_EXCEEDED = (counter) -> Integer.parseInt(counter) > RATE_COUNT;

    public Mono<Boolean> isRateLimited(String username) {
        return redisService
                .get(username)
                .flatMap(performRateLimitCheck(username));
    }

    public Mono<Void> incrementFailedLoginCount(String username) {
        return redisService.get(username)
                .flatMap(counter -> redisService.save(username, incrementValue(counter), Duration.ofMinutes(EXPIRY_DURATION)))
                .then();
    }
    public Mono<Boolean> resetRetryCount(String username) {
        return redisService.delete(username);
    }
    private Function<String, Mono<? extends Boolean>> performRateLimitCheck(String username) {
        return value -> Optional.ofNullable(value)
                .map(incrementRetryAndCheckIsRateLimitExceeded(username))
                .orElse(initializeRetryCounter(username));
    }

    private Mono<Boolean> initializeRetryCounter(String username) {
        return redisService.save(username, INITIAL_COUNT, Duration.ofMinutes(EXPIRY_DURATION))
                .thenReturn(Boolean.FALSE);
    }

    private Function<String, Mono<Boolean>> incrementRetryAndCheckIsRateLimitExceeded(String username) {
        return counter ->
                redisService.save(username, incrementValue(counter), Duration.ofMinutes(EXPIRY_DURATION))
                        .thenReturn(IS_RATE_LIMIT_EXCEEDED.test(counter));
    }

}
