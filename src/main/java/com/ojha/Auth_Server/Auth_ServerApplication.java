package com.ojha.Auth_Server;

import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.role.GeneralRoleRepository;
import com.ojha.Auth_Server.role.Role;
import com.ojha.Auth_Server.user.GeneralUserRepository;
import com.ojha.Auth_Server.user.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
public class Auth_ServerApplication {
    public static void main(String[] args) {
		SpringApplication.run(Auth_ServerApplication.class, args);
	}

	@Bean
	public CommandLineRunner runner(GeneralRoleRepository roleRepository, GeneralUserRepository userRepository) {

		return args -> {
			if (roleRepository.findByName("SUPER_ADMIN").isEmpty()) {
				roleRepository.save(Role.builder()
						.name("SUPER_ADMIN")
						.build());
			}
			if (roleRepository.findByName("ADMIN").isEmpty()) {
				roleRepository.save(Role.builder()
						.name("ADMIN")
						.build());
			}
			if (userRepository.findByEmail("codepaltech@gmail.com").isEmpty()) {
				final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
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
		};
	}
}
