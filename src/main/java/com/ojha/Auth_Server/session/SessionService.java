package com.ojha.Auth_Server.session;

import com.ojha.Auth_Server.auth.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;

public interface SessionService {

    Session createSessionId(String email);

    String findSessionIdByEmail(String email);

    Session verifyExpiration(Session session);

    AuthenticationResponse verifySessionId(String sessionId, String email, HttpServletRequest httpServletRequest);
}
