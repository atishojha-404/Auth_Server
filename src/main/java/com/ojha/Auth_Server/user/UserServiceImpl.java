package com.ojha.Auth_Server.user;

import com.ojha.Auth_Server.handler.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final GeneralUserRepository generalUserRepository;
    private final UserMapper userMapper;

    @Override
    public List<UserDto> getAllUsers() {
        try {
            List<User> userList = generalUserRepository.findAll();
            return userMapper.toDtoList(userList);
        }catch (Exception e){
            throw new CustomException("Error getting all users");
        }

    }

    @Override
    public UserDto getUserByEmail(String email) {
        try {
            User user = generalUserRepository.findUserByEmail(email);
            return userMapper.toDto(user);
        }catch (Exception e){
            throw new CustomException("Error getting user by email");
        }
    }

    @Override
    public UserDto getUserById(String id) {
        try {
            User user = generalUserRepository.findById(id).orElseThrow(() -> new RuntimeException("Cannot get user for id " +id));
            return userMapper.toDto(user);
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

    @Override
    public String lockUserAccount(String id) {
        try {
            Optional<User> optionalUser = generalUserRepository.findById(id);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();

                boolean isSuperAdmin = user.getAuthorities()
                        .parallelStream()
                        .anyMatch(i -> i.getAuthority().equals("SUPER_ADMIN"));

                if (isSuperAdmin) {
                    throw new CustomException("Account lock for SUPER ADMIN is not allowed");
                } else {
                    user.setAccountLocked(true);
                    generalUserRepository.save(user);
                    return "User account locked";
                }
            } else {
                throw new CustomException("User not found");
            }

        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

    @Override
    public String unLockUserAccount(String id) {
        try {
            Optional<User> optionalUser = generalUserRepository.findById(id);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();

                if (!(user.isAccountLocked())) {
                    throw new CustomException("Account is already unlocked");
                } else {
                    user.setAccountLocked(false);
                    generalUserRepository.save(user);
                    return "User account unlocked";
                }
            } else {
                throw new CustomException("User not found");
            }

        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

}
