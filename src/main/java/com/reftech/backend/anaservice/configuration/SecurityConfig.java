package com.reftech.backend.anaservice.configuration;

import com.reftech.backend.anaservice.filter.JWTAuthenticationFilter;
import com.reftech.backend.anaservice.manager.JwtReactiveAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Autowired
    private JWTAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private JwtReactiveAuthenticationManager jwtReactiveAuthenticationManager;


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authenticationManager(jwtReactiveAuthenticationManager)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth/login", "/auth/register").permitAll()  // Allow login and register without authentication
                        .pathMatchers("/auth/*").authenticated()  // Require authentication for refresh-token
                        .anyExchange().authenticated()  // Secure everything else (authenticated users only)
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
