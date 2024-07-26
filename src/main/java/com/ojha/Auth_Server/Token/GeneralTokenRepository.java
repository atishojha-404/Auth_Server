package com.ojha.Auth_Server.Token;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GeneralTokenRepository extends JpaRepository<Token, String> {

    Optional<Token> findByToken(String token);
}
