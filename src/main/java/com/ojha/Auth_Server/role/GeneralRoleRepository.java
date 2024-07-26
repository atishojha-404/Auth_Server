package com.ojha.Auth_Server.role;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GeneralRoleRepository extends JpaRepository<Role, String> {

    Optional<Role> findByName(String role);
}
