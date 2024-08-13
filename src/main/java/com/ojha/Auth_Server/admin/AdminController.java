package com.ojha.Auth_Server.admin;

import com.ojha.Auth_Server.auth.AuthenticationService;
import com.ojha.Auth_Server.auth.RegistrationRequest;
import com.ojha.Auth_Server.auth.RegistrationResponse;
import com.ojha.Auth_Server.constants.GlobalResponse;
import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.user.UserDto;
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
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin")
@Tag(name = "ADMIN")
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminController {

    private final UserService userService;
    private final AuthenticationService authenticationService;

    @RequestMapping(method = RequestMethod.POST, value = "/register-user")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> registerUser(@RequestBody @Valid RegistrationRequest request,
                                                                         HttpServletRequest httpServletRequest) {
        try {
            RegistrationResponse registrationResponse = authenticationService.registerUser(request);
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

    @RequestMapping(method = RequestMethod.GET, value = "/get-all-users")
    public ResponseEntity<GlobalResponse<List<UserDto>>> getAllUsers(HttpServletRequest httpServletRequest) {
        try {
            List<UserDto> users = userService.getAllUsers();
            GlobalResponse<List<UserDto>> response = GlobalResponse.<List<UserDto>>builder()
                    .data(users)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e){
            GlobalResponse<List<UserDto>> errorResponse = GlobalResponse.<List<UserDto>>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.GET, value = "/get-user-by-email")
    public ResponseEntity<GlobalResponse<UserDto>> getUserByEmail(@RequestParam String email,
                                                                  HttpServletRequest httpServletRequest) {
        try {
            UserDto users = userService.getUserByEmail(email);
            GlobalResponse<UserDto> response = GlobalResponse.<UserDto>builder()
                    .data(users)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e){
            GlobalResponse<UserDto> errorResponse = GlobalResponse.<UserDto>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .message(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.GET, value = "/get-user-by-id")
    public ResponseEntity<GlobalResponse<UserDto>> getUserById(@RequestParam String id,
                                                               HttpServletRequest httpServletRequest) {
        try {
            UserDto users = userService.getUserById(id);
            GlobalResponse<UserDto> response = GlobalResponse.<UserDto>builder()
                    .data(users)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .message("Operation Successful")
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e){
            GlobalResponse<UserDto> errorResponse = GlobalResponse.<UserDto>builder()
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
