package com.reftech.backend.anaservice.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Bean
    @Primary
    public ReactiveRedisConnectionFactory reactiveRedisConnectionFactory() {
        return new LettuceConnectionFactory("localhost", 6379);
    }


    @Bean
    @Primary
    public ReactiveRedisTemplate<String, String> reactiveRedisTemplate(ReactiveRedisConnectionFactory factory) {
        StringRedisSerializer serializer = new StringRedisSerializer();

        RedisSerializationContext<String, String> serializationContext = RedisSerializationContext
                .<String, String>newSerializationContext(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .key(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .value(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .hashKey(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .hashValue(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .build();

        return new ReactiveRedisTemplate<>(factory, serializationContext);
    }
}