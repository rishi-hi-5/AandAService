package com.reftech.backend.anaservice.repository;

import com.reftech.backend.anaservice.model.User;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UserRepository extends ReactiveCrudRepository<User, Long> {
    Mono<Boolean> existsByName(String username);
    Mono<Boolean> existsByEmail(String email);
    Mono<User> findByName(String username);
}
