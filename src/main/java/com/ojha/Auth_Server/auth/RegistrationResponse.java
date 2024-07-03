package com.ojha.Auth_Server.auth;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationResponse {

    private String userEmail;
    private String role;
    private String errorMessage;
}
