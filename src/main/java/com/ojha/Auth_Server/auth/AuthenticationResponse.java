package com.ojha.Auth_Server.auth;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private String accessToken;
    private String tokenType;
    private Long expiresIn;
    private String sessionId;
    private String userEmail;
    private String role;
    private boolean firstLogin;
    private String errorMessage;
}
