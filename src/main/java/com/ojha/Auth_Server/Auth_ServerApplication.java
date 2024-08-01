package com.ojha.Auth_Server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
public class Auth_ServerApplication {
    public static void main(String[] args) {
		SpringApplication.run(Auth_ServerApplication.class, args);
	}
}
