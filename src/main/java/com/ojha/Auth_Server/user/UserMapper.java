package com.ojha.Auth_Server.user;

import com.ojha.Auth_Server.role.RoleMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring", uses = RoleMapper.class)
public interface UserMapper {
    UserDto toDto(User user);
    User toEntity(UserDto userDto);
    @Mapping(target = "roles")
    List<UserDto> toDtoList(List<User> userList);
    List<User> toEntityList(List<UserDto> userDtoList);
}
