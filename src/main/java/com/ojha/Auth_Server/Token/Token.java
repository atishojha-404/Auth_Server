package com.ojha.Auth_Server.Token;

import com.ojha.Auth_Server.user.User;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "token")
public class Token {
//    This is OTP code for use not JWT

    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private String id;
    private String token;
    private String tokenType;

    @Column(name = "created_at")
    private Long createdAt;
    @Column(name = "expires_at")
    private Long expiresAt;
    @Column(name = "validated_at")
    private Long validatedAt;

    @ManyToOne
    @JoinColumn(name = "userId", nullable = false)
    private User user;

}
