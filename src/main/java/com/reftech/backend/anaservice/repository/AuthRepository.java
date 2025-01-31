package com.reftech.backend.anaservice.repository;


import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthRepository extends R2dbcRepository<AuthRepository, Long> { // the r2db template no valid
}
