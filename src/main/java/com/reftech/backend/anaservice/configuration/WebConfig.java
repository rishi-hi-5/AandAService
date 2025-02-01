package com.reftech.backend.anaservice.configuration;


import com.reftech.backend.anaservice.filter.JWTAuthenticationFilter;
import org.springframework.web.server.WebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebConfig {

    @Bean
    public WebFilter jwtAuthenticationFilter() {
        return new JWTAuthenticationFilter();
    }
}
