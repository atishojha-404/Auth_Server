package com.ojha.Auth_Server.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface GeneralUserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmail(String email);

    @Query(value = "Select * from user where email like :email", nativeQuery = true)
    User findUserByEmail(@Param("email") String email);
}
