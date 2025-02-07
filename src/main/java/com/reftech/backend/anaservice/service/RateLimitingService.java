package com.reftech.backend.anaservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.function.Function;

import static com.reftech.backend.anaservice.model.Constants.*;
import static com.reftech.backend.anaservice.utility.StringIntegerUtility.incrementValue;

@Component
@Slf4j
@RequiredArgsConstructor
public class RateLimitingService {

    private final RedisService redisService;
    private static final Function<String, Boolean> IS_RATE_LIMIT_EXCEEDED = counter -> Integer.parseInt(counter) > RATE_COUNT;

    /**
     * Checks if the user is rate-limited based on failed login attempts.
     */
    public Mono<Boolean> isRateLimited(String username) {
        return redisService.get(username)
                .doOnSuccess(value -> log.info("Token value from Redis: {}", value))
                .flatMap(value->evaluateRateLimit(username,value))  // Use a direct method for readability
                .defaultIfEmpty(Boolean.FALSE);    // Ensure default value if Redis key is absent
    }

    /**
     * Increments failed login attempt count for the user.
     */
    public Mono<Void> incrementFailedLoginCount(String username) {
        return redisService.get(username)
                .flatMap(counter -> redisService.save(username, incrementValue(counter), Duration.ofMinutes(EXPIRY_DURATION)))
                .then();
    }

    /**
     * Resets the retry count by deleting the Redis key.
     */
    public Mono<Boolean> resetRetryCount(String username) {
        return redisService.delete(username);
    }

    /**
     * Evaluates if the retry count has exceeded the rate limit.
     */
    private Mono<Boolean> evaluateRateLimit(String username, String value) {
        return value.isEmpty() ? initializeRetryCounter(username) : incrementRetryAndCheckLimit(username,value);
    }

    /**
     * Initializes the retry counter in Redis.
     */
    private Mono<Boolean> initializeRetryCounter(String username) {
        return redisService.save(username, INITIAL_COUNT, Duration.ofMinutes(EXPIRY_DURATION))
                .doOnSuccess(saved -> log.info("Initialized retry counter in Redis"))
                .thenReturn(Boolean.FALSE);
    }

    /**
     * Increments the retry counter and checks if the limit is exceeded.
     */
    private Mono<Boolean> incrementRetryAndCheckLimit(String username, String value) {
        return redisService.save(username, incrementValue(value), Duration.ofMinutes(EXPIRY_DURATION))
                .doOnSuccess(updatedValue -> log.info("Updated retry counter in Redis: {}", updatedValue))
                .map(updatedValue -> IS_RATE_LIMIT_EXCEEDED.apply(value));
    }
}
