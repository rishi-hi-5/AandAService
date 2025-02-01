package com.reftech.backend.anaservice.filter;

import com.reftech.backend.anaservice.service.TokenBlackListService;
import com.reftech.backend.anaservice.service.TokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

public class JWTAuthenticationFilter implements WebFilter {

    @Autowired
    private TokenBlackListService tokenBlackListService;

    @Autowired
    private TokenService tokenService;

    public static final Predicate<String> pathDoesntNeedAuthentication = path ->
            path.equals("/auth/login") ||
            path.equals("/auth/register");

    public static final Predicate<List<Object>> checkAllInvalidFlags = flags->
            flags
                    .stream()
                    .map(Boolean.class::cast)
                    .reduce(Boolean.TRUE, (a,b)-> a && b);


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String requestURI = exchange.getRequest().getURI().getPath();
        if (pathDoesntNeedAuthentication.test(requestURI)) {
            return chain.filter(exchange);
        }

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return tokenService
                .extractToken(authorization)
                .flatMap(token-> Mono.zip(tokenBlackListService.isBlackListed(token), tokenService.isExpired(token)))
                        .flatMap(checkForInvalidityOfTokenAndMoveToNextFilter(exchange, chain))
                .then();

    }

    private static Function<Tuple2<Boolean, Boolean>, Mono<? extends Void>> checkForInvalidityOfTokenAndMoveToNextFilter(ServerWebExchange exchange, WebFilterChain chain) {
        return invalidFlags -> {
            if (checkAllInvalidFlags.test(invalidFlags.toList())) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getResponse().getHeaders().set("Error", "Token is invalid or expired");
                return exchange.getResponse().setComplete();
            }
            return chain.filter(exchange);
        };
    }
}
