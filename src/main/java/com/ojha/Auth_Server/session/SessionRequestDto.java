package com.ojha.Auth_Server.session;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SessionRequestDto {

    private String sessionId;
    private String email;
}
