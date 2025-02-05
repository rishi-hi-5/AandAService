package com.reftech.backend.anaservice.service;

import com.reftech.backend.anaservice.api.*;
import com.reftech.backend.anaservice.manager.JwtReactiveAuthenticationManager;
import com.reftech.backend.anaservice.model.User;
import com.reftech.backend.anaservice.repository.AnAUserDetailsService;
import com.reftech.backend.anaservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuple3;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

@Service
@Slf4j
public class AuthService {
    @Autowired
    @Lazy
    private JwtReactiveAuthenticationManager authenticationManager;

    @Autowired
    private AnAUserDetailsService userDetailsService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private RateLimitingService rateLimitingService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenBlackListService tokenBlackListService;

    public static final Predicate<List<Object>> checkAllInvalidFlags = flags->
            flags
                    .stream()
                    .map(Boolean.class::cast)
                    .reduce(Boolean.TRUE, (a,b)-> a && b);

    public Mono<LoginUser200Response> login(Mono<LoginUserRequest> loginUserRequestMono) {
        return loginUserRequestMono
                .doOnNext(loginUserRequest -> log.info("Login request for user {}", loginUserRequest.getUsername()))
                .doOnError(throwable -> log.error("Error while processing login request", throwable))
                .flatMap(checkRateLimit())
                .doOnNext(loginUserRequest -> log.info("Rate limit check passed for user {}", loginUserRequest.getUsername()))
                .doOnError(throwable -> log.error("Error while checking rate limit", throwable))
                .flatMap(authenticateUser())
                .doOnNext(tokens -> log.info("Token generated for user {} ", tokens.getT1()))
                .doOnError(throwable -> log.error("Error while authenticating user", throwable))
                .flatMap(mapTokenToResponse())
                .doOnNext(loginUser200Response -> log.info("User {} logged in", loginUser200Response.getAccessToken()) )
                .doOnError(throwable -> log.error("Error while mapping token to response", throwable))
                .log();
    }

    public Mono<Void> register(Mono<RegisterUserRequest> registerUserRequestMono) {
        return registerUserRequestMono
                .flatMap(registerUserRequest -> userRepository.existsByUsername(registerUserRequest.getUsername())
                        .flatMap(checkIfUserNameAlreadyExists(registerUserRequest))
                        .flatMap(checkIfUserEmailAlreadyExists(registerUserRequest))
                        .then());
    }

    public Mono<RefreshToken200Response> refreshToken(Mono<RefreshTokenRequest> refreshTokenRequestMono) {
        return refreshTokenRequestMono
                .flatMap(refreshTokenRequest -> {
                    String userName = refreshTokenRequest.getUsername();
                    String refreshToken = refreshTokenRequest.getRefreshToken();

                    return Mono.zip(tokenBlackListService.isBlackListed(refreshToken), tokenService.isExpired(refreshToken))
                            .flatMap(createNewTokenIfRefreshTokenIsNotInvalid(userName));
                });
    }

    public Mono<GetUserDetails200Response> getUserDetails(String userName) {
        return userRepository
                .findByUsername(userName)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(userData -> Optional.ofNullable(userData)
                        .map(user->{
                            GetUserDetails200Response userResponse = new GetUserDetails200Response();
                            userResponse.setId(user.getId().toString());
                            userResponse.setUsername(user.getUsername());
                            userResponse.setEmail(user.getEmail());
                            userResponse.setRole(user.getRole());
                            return Mono.just(userResponse);
                        })
                        .orElse(Mono.error(new RuntimeException("User not found"))));
    }

    private Function<Tuple2<Boolean, Boolean>, Mono<? extends RefreshToken200Response>> createNewTokenIfRefreshTokenIsNotInvalid(String userName) {
        return invalidFlags -> {
            if (checkAllInvalidFlags.test(invalidFlags.toList())) {
                return Mono.error(new RuntimeException("Token is invalid or expired"));
            }
            return Mono.zip(tokenService.generateAccessToken(userName),tokenService.generateRefreshToken(userName))
                        .flatMap(createTokens());
        };
    }

    private static Function<Tuple2<String, String>, Mono<? extends RefreshToken200Response>> createTokens() {
        return tokens -> {
            RefreshToken200Response refreshToken200Response = new RefreshToken200Response();
            refreshToken200Response.setAccessToken(tokens.getT1());
            refreshToken200Response.setRefreshToken(tokens.getT2());
            return Mono.just(refreshToken200Response);
        };
    }

    public Mono<Void> logout(String authorization, String username) {
        return tokenService.extractToken(authorization)
                .flatMap(token->tokenBlackListService
                        .blackList(token)
                        .flatMap(blackListed -> {
                            log.info("username {} logged out", username);
                            return Mono.empty();
                        }));
    }

    private Function<LoginUserRequest, Mono<? extends Tuple3<String, String,Boolean>>> authenticateUser() {
        return authenticationDetails -> authenticationManager // this is needed basiclly to be future proof with LDAP
                .authenticate(new UsernamePasswordAuthenticationToken(
                        authenticationDetails.getUsername(),authenticationDetails.getPassword()))
                .doOnNext(auth-> log.info("Authentication successful for user {}", auth.getName()))
                .flatMap(obtainTokensAndResetRateLimit())
                .doOnError(throwable -> log.error("Error while authenticating user", throwable))
                .log();
    }

    private Function<LoginUserRequest, Mono<? extends LoginUserRequest>> checkRateLimit() {
        return loginUserRequest -> rateLimitingService
                .isRateLimited(loginUserRequest.getUsername())
                .doOnNext(isRateLimited -> log.info("Rate limit check for user {} is {}", loginUserRequest.getUsername(), isRateLimited))
                .doOnError(throwable -> log.error("Error while checking rate limit", throwable))
                .flatMap(isRateLimited -> {
                    if (isRateLimited) {
                        return Mono.error(new RuntimeException("Number of retry for login has exceeded the limit. Please try again later."));
                    }
                    return Mono.just(loginUserRequest);
                })
                .doOnNext(loginUserRequest2 -> log.info("Rate limit check passed for user {}", loginUserRequest2.getUsername()))
                .doOnError(throwable -> log.error("Error while checking rate limit", throwable)).log();
    }

    private Function<Tuple3<String, String,Boolean>, Mono<? extends LoginUser200Response>> mapTokenToResponse() {
        return tokens -> {
            Boolean rateLimitResetSuccess = tokens.getT3();
            if(!rateLimitResetSuccess) {
                log.warn("Failed to reset rate limit count");
            }

            LoginUser200Response loginUser200Response = new LoginUser200Response();
            loginUser200Response.setAccessToken(tokens.getT1());
            loginUser200Response.setRefreshToken(tokens.getT2());
            return Mono.just(loginUser200Response);
        };
    }

    private Function<Authentication, Mono<? extends Tuple3<String, String,Boolean>>> obtainTokensAndResetRateLimit() {
        return authentication -> {
            String userName = authentication.getName();
            if (authentication.isAuthenticated()) {
                return Mono.zip(
                        tokenService.generateAccessToken(userName),
                        tokenService.generateRefreshToken(userName),
                        rateLimitingService.resetRetryCount(userName));
            }

            return rateLimitingService
                    .incrementFailedLoginCount(userName)
                    .then(Mono.error(new RuntimeException("Invalid credentials")));
        };
    }


    private Function<Boolean, Mono<? extends User>> checkIfUserEmailAlreadyExists(RegisterUserRequest registerUserRequest) {
        return emailExists -> {
            if (emailExists) {
                return Mono.error(new RuntimeException("Email already exists"));
            }

            String hashedPassword = bCryptPasswordEncoder.encode(registerUserRequest.getPassword());
            User newUser = new User();
            newUser.setUsername(registerUserRequest.getUsername());
            newUser.setPassword(hashedPassword);
            newUser.setEmail(registerUserRequest.getEmail());
            newUser.setRole("USER");

            return userRepository.save(newUser);
        };
    }

    private Function<Boolean, Mono<? extends Boolean>> checkIfUserNameAlreadyExists(RegisterUserRequest registerUserRequest) {
        return usernameExists -> {
            if (usernameExists) {
                return Mono.error(new RuntimeException("Username already exists"));
            }
            return userRepository.existsByEmail(registerUserRequest.getEmail());
        };
    }
}
