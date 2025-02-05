package com.reftech.backend.anaservice.manager;

import com.reftech.backend.anaservice.repository.AnAUserDetailsService;
import com.reftech.backend.anaservice.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
        return authenticateUsernameAndPassword((UsernamePasswordAuthenticationToken) authentication);
    }

    private Mono<Authentication> authenticateUsernameAndPassword(UsernamePasswordAuthenticationToken authentication) {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        return userDetailsService.findByUsername(username)
                .flatMap(userDetails -> {
                    if (new BCryptPasswordEncoder().matches(password, userDetails.getPassword())) {
                        return Mono.just((Authentication) new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
                    } else {
                        return Mono.error(new RuntimeException("Invalid credentials"));
                    }
                })
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")));
    }
}
