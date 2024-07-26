package com.ojha.Auth_Server.role;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.ojha.Auth_Server.user.User;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "role")
@EntityListeners(AuditingEntityListener.class)
public class Role {

    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private String id;

    @Column(unique = true)
    private String name;

    @ManyToMany(mappedBy = "roles")
    @JsonIgnore
    private List<User> users;

    @CreatedDate
    @Column(name = "created_date", nullable = false, updatable = false)
    private Long createdDate = Instant.now().toEpochMilli();
    @LastModifiedDate
    @Column(name = "last_modified_date", insertable = false)
    private Long lastModifiedDate = Instant.now().toEpochMilli();



}
