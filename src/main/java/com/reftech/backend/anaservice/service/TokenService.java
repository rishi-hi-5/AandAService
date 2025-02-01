package com.reftech.backend.anaservice.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static com.reftech.backend.anaservice.model.Constants.REFRESH_TOKEN_EXPIRATION;
import static com.reftech.backend.anaservice.model.Constants.TOKEN_EXPIRATION;


@Slf4j
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

    public Mono<Boolean> isExpired(String token) {
        return Mono.fromCallable(()->{
           try{
                Claims claims = Jwts
                        .parser()
                        .verifyWith(secret)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
                log.debug("Token is valid with claims [{}]",claims);
           } catch (Exception e) {
                log.warn("Token is invalid",e);
           }
              return false;
        });
    }

    public String extractUsername(String token) {
        try {
            Claims claims = Jwts
                    .parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getSubject();
        } catch (Exception e) {
            log.warn("Exception occurred while extracting username",e);
            throw e;
        }
    }

    public Mono<String> extractToken(String authorization) {
        String token;
        if (authorization != null && authorization.startsWith("Bearer ")) {
            token = authorization.substring(7);
        } else {
            return Mono.error(new RuntimeException("Invalid token"));
        }
        return Mono.just(token);
    }

    private static Date expireAt(Long expirationTime) {
        return new Date(System.currentTimeMillis() + expirationTime);
    }

    private static Date currentDate() {
        return new Date();
    }

    public Mono<Boolean> isNotValid(String token) {
        return validateToken(token)
                .map(valid -> !valid);
    }

    public Mono<Boolean> validateToken(String token) {
        try{
            Claims claims = Jwts
                    .parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (claims.getExpiration().before(currentDate())) {
                return Mono.just(Boolean.FALSE);
            }
            return Mono.just(Boolean.TRUE);
        } catch (Exception e) {
            log.warn("Exception occured while validating token",e);
            throw e;
        }
    }
}
