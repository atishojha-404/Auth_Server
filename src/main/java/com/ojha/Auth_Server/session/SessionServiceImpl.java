package com.ojha.Auth_Server.session;

import com.ojha.Auth_Server.auth.AuthenticationResponse;
import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.security.JwtService;
import com.ojha.Auth_Server.user.GeneralUserRepository;
import com.ojha.Auth_Server.user.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SessionServiceImpl implements SessionService {

    @Value("${application.security.session.expiration}")
    private Long SESSION_EXPIRE_IN;

    @Value("${application.security.jwt.expiration}")
    private Long JWT_TOKEN_EXPIRE_IN;

    private final GeneralSessionRepository generalSessionRepository;
    private final GeneralUserRepository generalUserRepository;
    private final JwtService jwtService;

    @Override
    public Session createSessionId(String email) {
        try {
            Session session = Session.builder()
                    .user(generalUserRepository.findUserByEmail(email))
                    .sessionId(UUID.randomUUID().toString())
                    .createdAt(Instant.now().toEpochMilli())
                    .expiresAt(Instant.now().toEpochMilli() + SESSION_EXPIRE_IN)
                    .valid(true)
                    .build();
            return generalSessionRepository.save(session);
        }catch (CustomException e){
            throw new CustomException("User with email '" + email + "' not exists");
        }

    }

    @Override
    public String findSessionIdByEmail(String email) {
        try {
            return generalSessionRepository.findSessionIdByEmail(email);
        }catch (CustomException e){
            throw new CustomException("Something went wrong when trying to find session id by email '" + email + "'");
        }
    }

    @Override
    public Session verifyExpiration(Session session) {
        try {
            if(session.getExpiresAt().compareTo(Instant.now().toEpochMilli()) < 0) {
                Session session1 = generalSessionRepository.findBySessionId(session.getSessionId()).get();
                session1.setValid(false);
                generalSessionRepository.save(session1);
                throw new CustomException("Session expired");
            }
            return session;
        }catch (CustomException e){
            throw new CustomException("Session expired");
        }
    }

    @Override
    public AuthenticationResponse verifySessionId(String sessionId, String email, HttpServletRequest httpServletRequest) {
        try {
            Session session = generalSessionRepository.findBySessionId(sessionId).orElseThrow(() -> new CustomException("Invalid Session"));
            String sessionIdByEmail = findSessionIdByEmail(email);

            String headerSessionId = null;
            String authorizationHeader = httpServletRequest.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String token = authorizationHeader.substring(7); // Remove "Bearer " prefix
                headerSessionId = jwtService.extractSessionId(token);
            }

            if (session == null || !sessionId.equals(sessionIdByEmail) || !sessionId.equals(headerSessionId)) {
                throw new CustomException("Invalid Session");
            }

            Session verifiedSession = verifyExpiration(session);

            verifiedSession.setExpiresAt(Instant.now().toEpochMilli() + SESSION_EXPIRE_IN);
            generalSessionRepository.save(verifiedSession);

            var claims = new HashMap<String, Object>();
            User user = verifiedSession.getUser();
            claims.put("email", user.getUsername());
            claims.put("session_id", verifiedSession.getSessionId());
            String accessToken = jwtService.generateTokenForSession(claims, user.getUsername(), user.getAuthorities());

            return AuthenticationResponse.builder()
                    .userEmail(user.getUsername())
                    .accessToken(accessToken)
                    .sessionId(verifiedSession.getSessionId())
                    .role(user.getAuthorities().toString())
                    .tokenType("Bearer")
                    .expiresIn(Instant.now().toEpochMilli() + JWT_TOKEN_EXPIRE_IN)
                    .build();

        }catch (CustomException e){
            throw new CustomException("Invalid Session");
        }

    }

}
