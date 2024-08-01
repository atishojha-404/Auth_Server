package com.ojha.Auth_Server.user;

import java.util.List;

public interface UserService {

    List<UserDto> getAllUsers();

    UserDto getUserByEmail(String email);

    UserDto getUserById(String id);

    String lockUserAccount(String id);

    String unLockUserAccount(String id);
}
