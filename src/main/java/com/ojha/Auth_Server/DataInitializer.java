package com.ojha.Auth_Server;

import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.role.GeneralRoleRepository;
import com.ojha.Auth_Server.role.Role;
import com.ojha.Auth_Server.user.GeneralUserRepository;
import com.ojha.Auth_Server.user.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.boot.CommandLineRunner;

import java.util.List;

@Component
public class DataInitializer implements CommandLineRunner {

    private final GeneralRoleRepository roleRepository;
    private final GeneralUserRepository userRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public DataInitializer(GeneralRoleRepository roleRepository, GeneralUserRepository userRepository) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }


    @Override
    public void run(String... args) {
        initializeRole("SUPER_ADMIN");
        initializeRole("ADMIN");
        initializeAdminUser();
    }

    private void initializeRole(String roleName) {
        if (roleRepository.findByName(roleName).isEmpty()) {
            roleRepository.save(Role.builder()
                    .name(roleName)
                    .build());
        }
    }

    private void initializeAdminUser() {
        if (userRepository.findByEmail("admin@gmail.com").isEmpty()) {
            var userRole = roleRepository.findByName("SUPER_ADMIN")
                    .orElseThrow(() -> new CustomException("ROLE was not initialized, Contact to admin."));
            userRepository.save(User.builder()
                    .email("admin@gmail.com")
                    .password(passwordEncoder.encode("password"))
                    .accountLocked(false)
                    .enabled(false)
                    .roles(List.of(userRole))
                    .build());
        }
    }
}
