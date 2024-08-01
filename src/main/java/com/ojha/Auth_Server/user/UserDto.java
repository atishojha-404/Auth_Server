package com.ojha.Auth_Server.user;

import com.ojha.Auth_Server.role.RoleDto;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.util.List;


@Getter
@Setter
@ToString
@NoArgsConstructor
public class UserDto {

    private String id;
    private String email;
    private boolean accountLocked;
    private boolean enabled;
    private Long createdDate;
    private Long lastModifiedDate;
    private List<RoleDto> roles;

}
