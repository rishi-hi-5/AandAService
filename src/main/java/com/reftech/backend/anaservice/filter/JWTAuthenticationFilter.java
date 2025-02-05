package com.reftech.backend.anaservice.filter;

import com.reftech.backend.anaservice.manager.JwtReactiveAuthenticationManager;
import com.reftech.backend.anaservice.service.TokenBlackListService;
import com.reftech.backend.anaservice.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.function.Predicate;

@Component

@Slf4j
public class JWTAuthenticationFilter implements WebFilter {

    @Autowired
    private TokenBlackListService tokenBlackListService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private ReactiveUserDetailsService userDetailsService;

    @Autowired
    private JwtReactiveAuthenticationManager authenticationManager;
    public static final Predicate<String> pathDoesntNeedAuthentication = path ->
            path.contains("/auth/login") ||
            path.contains("/auth/register") ||
            path.contains("/ana-service/v3/api-docs") ||
            path.contains("/swagger-ui") ;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String requestURI = exchange.getRequest().getURI().getPath();
        if (pathDoesntNeedAuthentication.test(requestURI)) {
            return chain.filter(exchange);
        }

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String userName = exchange.getRequest().getQueryParams().getFirst("username");
        return tokenService
                .extractToken(authorization)
                .doOnTerminate(() -> log.info("Token extraction completed"))
                .switchIfEmpty(Mono.error(new RuntimeException("Token is missing or invalid")))  // Handle missing token
                .flatMap(token-> tokenBlackListService.isBlackListed(token))
                .doOnSuccess(isBlackListed -> log.info("is blacklisted check completed {}",isBlackListed))
                .doOnTerminate(() -> log.info("is blacklisted check completed"))
                .onErrorResume(e -> {
                    log.error("Error in the blacklist check", e);
                    return Mono.error(e); // propagate the error
                })
                .flatMap(isBlackListed -> {
                            log.info("is Token blacklisted: {}", isBlackListed);
                            if (isBlackListed){
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                exchange.getResponse().getHeaders().set("Error", "Token is invalid or expired");
                                return exchange.getResponse().setComplete().doOnTerminate(() -> log.info("Response completion after blacklist check"));
                            }

                            return tokenService
                                    .extractToken(authorization)
                                    .flatMap(token -> tokenService.validateToken(token, userName))
                                    .then(chain.filter(exchange));
                        });

    }

}
