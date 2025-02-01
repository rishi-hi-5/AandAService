package com.reftech.backend.anaservice.service;

import com.reftech.backend.anaservice.api.LoginUser200Response;
import com.reftech.backend.anaservice.api.LoginUserRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.util.function.Function;

@Service
public class AuthService {
    @Autowired
    private ReactiveAuthenticationManager authenticationManager;

    @Autowired
    private ReactiveUserDetailsService userDetailsService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private RateLimitingService rateLimitingService;

    public Mono<LoginUser200Response> login(Mono<LoginUserRequest> loginUserRequestMono) {
        Mono<UserDetails> userDetails = loginUserRequestMono
                .flatMap(checkRateLimit())
                .flatMap(getUserDetails());

        return Mono.zip(userDetails, loginUserRequestMono)
                .flatMap(authenticateUser())
                .flatMap(mapTokenToResponse());
    }

    private Function<Tuple2<UserDetails, LoginUserRequest>, Mono<? extends Tuple2<String, String>>> authenticateUser() {
        return authenticationDetails -> authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(authenticationDetails.getT2().getUsername(), authenticationDetails.getT2().getPassword()))
                .flatMap(obtainTokens(authenticationDetails));
    }

    private Function<LoginUserRequest, Mono<? extends UserDetails>> getUserDetails() {
        return loginUserRequest -> userDetailsService.findByUsername(loginUserRequest.getUsername());
    }

    private Function<LoginUserRequest, Mono<? extends LoginUserRequest>> checkRateLimit() {
        return loginUserRequest -> rateLimitingService
                .isRateLimited(loginUserRequest.getUsername())
                .flatMap(isRateLimited -> {
                    if (isRateLimited) {
                        return Mono.error(new RuntimeException("Number of retry for login has exceeded the limit. Please try again later."));
                    }
                    return Mono.just(loginUserRequest);
                });
    }

    private static Function<Tuple2<String, String>, Mono<? extends LoginUser200Response>> mapTokenToResponse() {
        return tokens -> {
            LoginUser200Response loginUser200Response = new LoginUser200Response();
            loginUser200Response.setAccessToken(tokens.getT1());
            loginUser200Response.setRefreshToken(tokens.getT2());
            return Mono.just(loginUser200Response);
        };
    }

    private Function<Authentication, Mono<? extends Tuple2<String, String>>> obtainTokens(Tuple2<UserDetails, LoginUserRequest> authenticationDetails) {
        return authentication -> {
            if (authentication.isAuthenticated()) {
                return Mono.zip(
                        tokenService.generateAccessToken(authenticationDetails.getT1().getUsername()),
                        tokenService.generateRefreshToken(authenticationDetails.getT1().getUsername()),
                        rateLimitingService.resetRetryCount(authenticationDetails.getT1().getUsername()));
            }

            return rateLimitingService
                    .incrementFailedLoginCount(authenticationDetails.getT1().getUsername())
                    .then(Mono.error(new RuntimeException("Invalid credentials")));
        };
    }
}
