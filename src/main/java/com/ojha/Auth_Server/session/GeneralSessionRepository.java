package com.ojha.Auth_Server.session;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GeneralSessionRepository extends JpaRepository<Session, String> {

    Optional<Session> findBySessionId(String sessionId);

    @Query(nativeQuery = true, value = "Select session_id from session s left join user u on s.user_id = u.id where u.email like :email and s.valid = true ")
    String findSessionIdByEmail(@Param("email") String email);
}
