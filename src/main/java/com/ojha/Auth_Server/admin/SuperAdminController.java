package com.ojha.Auth_Server.admin;

import com.ojha.Auth_Server.auth.AuthenticationService;
import com.ojha.Auth_Server.auth.RegistrationRequest;
import com.ojha.Auth_Server.auth.RegistrationResponse;
import com.ojha.Auth_Server.constants.GlobalResponse;
import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.user.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/super-admin")
@Tag(name = "SuperAdmin")
@PreAuthorize("hasAuthority('SUPER_ADMIN')")
public class SuperAdminController {

    private final AuthenticationService authenticationService;
    private final UserService userService;

    @RequestMapping(method = RequestMethod.POST, value = "/register-admin")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> registerAdmin(@RequestBody @Valid RegistrationRequest request,
                                                                         HttpServletRequest httpServletRequest) {
        try {
            RegistrationResponse registrationResponse = authenticationService.registerAdmin(request);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.ACCEPTED.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful.")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (AuthenticationException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        } catch (MessagingException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.PUT, value = "/lock-user-account")
    public ResponseEntity<GlobalResponse<String>> lockUserAccount(@RequestParam String id,
                                                                  HttpServletRequest httpServletRequest) {
        try {
            String message = userService.lockUserAccount(id);
            GlobalResponse<String> response = GlobalResponse.<String>builder()
                    .data(message)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e){
            GlobalResponse<String> errorResponse = GlobalResponse.<String>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.PUT, value = "/unlock-user-account")
    public ResponseEntity<GlobalResponse<String>> unLockUser(@RequestParam String id,
                                                             HttpServletRequest httpServletRequest) {
        try {
            String message = userService.unLockUserAccount(id);
            GlobalResponse<String> response = GlobalResponse.<String>builder()
                    .data(message)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e){
            GlobalResponse<String> errorResponse = GlobalResponse.<String>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

}
