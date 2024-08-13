package com.ojha.Auth_Server.user;

import com.ojha.Auth_Server.constants.GlobalResponse;
import com.ojha.Auth_Server.handler.CustomException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@Tag(name = "User")
@PreAuthorize("hasAuthority('USER')")
public class UserController {

    @RequestMapping(method = RequestMethod.GET, value = "/test")
    public ResponseEntity<GlobalResponse<String>> logout(HttpServletRequest httpServletRequest) {
        try {
            GlobalResponse<String > globalResponse = GlobalResponse.<String>builder()
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Test API")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (CustomException e) {
            GlobalResponse<String> errorResponse = GlobalResponse.<String>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        }
    }
}
