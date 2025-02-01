package com.reftech.backend.anaservice.manager;

import com.reftech.backend.anaservice.repository.AnAUserDetailsService;
import com.reftech.backend.anaservice.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AnAUserDetailsService userDetailsService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        String token = authentication.getCredentials().toString();

        return tokenService.validateToken(token)
                .flatMap(isValid -> {
                    if (isValid) {
                        return userDetailsService
                                .findByUsername(tokenService.extractUsername(token))
                                .map(userDetails -> new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
                    } else {
                        return Mono.empty();
                    }
                });
    }
}
