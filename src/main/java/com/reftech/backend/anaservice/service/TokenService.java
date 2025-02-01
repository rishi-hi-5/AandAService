package com.reftech.backend.anaservice.service;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static com.reftech.backend.anaservice.model.Constants.REFRESH_TOKEN_EXPIRATION;
import static com.reftech.backend.anaservice.model.Constants.TOKEN_EXPIRATION;

@Service
public class TokenService {
    private final SecretKey secret;

    public TokenService(@Value("${jwt.secret}") String secret) {
        this.secret = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    public Mono<String> generateAccessToken(String username) {
        return Mono.just(Jwts.builder()
                .subject(username)
                .issuedAt(currentDate())
                .expiration(expireAt(TOKEN_EXPIRATION))
                .signWith(secret)
                .compact());
    }


    public Mono<String> generateRefreshToken(String username) {
        return Mono.just(Jwts.builder()
                .subject(username)
                .issuedAt(currentDate())
                .expiration(expireAt(REFRESH_TOKEN_EXPIRATION))
                .signWith(secret)
                .compact());
    }
    private static Date expireAt(Long expirationTime) {
        return new Date(System.currentTimeMillis() + expirationTime);
    }

    private static Date currentDate() {
        return new Date();
    }
}
