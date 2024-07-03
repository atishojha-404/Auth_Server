package com.ojha.Auth_Server.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {

    @Email(message = "Email is not formatted.")
    @NotNull(message = "Email is mandatory.")
    @NotBlank(message = "Email is mandatory.")
    private String email;

    @NotNull(message = "Password is mandatory.")
    @NotBlank(message = "Password is mandatory.")
    @Size(message = "Password should be 8 characters lon minimum.")
    private String password;
}
