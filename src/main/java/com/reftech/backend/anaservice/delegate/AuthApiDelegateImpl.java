package com.reftech.backend.anaservice.delegate;

import com.reftech.backend.anaservice.api.AuthApiDelegate;
import com.reftech.backend.anaservice.api.LoginUser200Response;
import com.reftech.backend.anaservice.api.LoginUserRequest;
import com.reftech.backend.anaservice.api.RegisterUserRequest;
import com.reftech.backend.anaservice.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthApiDelegateImpl implements AuthApiDelegate {

    @Autowired
    private AuthService authService;

    @Override
    public Mono<ResponseEntity<LoginUser200Response>> loginUser(Mono<LoginUserRequest> loginUserRequest,ServerWebExchange exchange) {
        return authService
                .login(loginUserRequest)
                .map(ResponseEntity::ok);
    }


    @Override
    public Mono<ResponseEntity<Void>> registerUser(Mono<RegisterUserRequest> registerUserRequest,
                                                    ServerWebExchange exchange) {
        return authService
                .register(registerUserRequest)
                .map(ResponseEntity::ok);
    }


    @Override
    public Mono<ResponseEntity<Void>> logoutUser(String authorization,
                                                  String username,
                                                  ServerWebExchange exchange) {
        return authService
                .logout(authorization,username)
                .map(ResponseEntity::ok);
    }
}
