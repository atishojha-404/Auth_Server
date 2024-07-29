package com.ojha.Auth_Server.auth;

import com.ojha.Auth_Server.constants.GlobalResponse;
import com.ojha.Auth_Server.handler.CustomException;
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
import java.util.Objects;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PreAuthorize("hasAuthority('SUPER_ADMIN')")
    @RequestMapping(method = RequestMethod.POST, value = "/register")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> register(@RequestBody @Valid RegistrationRequest request, HttpServletRequest httpServletRequest) {
        try {
            RegistrationResponse registrationResponse = authenticationService.register(request);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.ACCEPTED.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (AuthenticationException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        } catch (MessagingException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }


    @RequestMapping(method = RequestMethod.POST, value = "/authenticate")
    public ResponseEntity<GlobalResponse<AuthenticationResponse>> authenticate(@RequestBody @Valid AuthenticationRequest request, HttpServletRequest httpServletRequest) {
        try {
            AuthenticationResponse authenticationResponse = authenticationService.authenticate(request);
            GlobalResponse<AuthenticationResponse> globalResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .data(authenticationResponse)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (AuthenticationException e) {
            GlobalResponse<AuthenticationResponse> errorResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (CustomException e) {
            GlobalResponse<AuthenticationResponse> errorResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        } catch (MessagingException e) {
            GlobalResponse<AuthenticationResponse> errorResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<AuthenticationResponse> errorResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.GET, value = "/activate-account")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> confirm(@RequestParam String email, @RequestParam String token, HttpServletRequest httpServletRequest){
        try {
            RegistrationResponse registrationResponse = authenticationService.activateAccount(email, token);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.ACCEPTED.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        } catch (MessagingException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/change-password-email")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> processChangePassword(@RequestParam String email, HttpServletRequest httpServletRequest) {
        try {
            RegistrationResponse registrationResponse = authenticationService.sendChangePassOTP(email);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.ACCEPTED.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        }catch (MessagingException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.GET, value = "/change-password-token-confirm")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> confirmForgotPassCode(@RequestParam String email, @RequestParam String token, HttpServletRequest httpServletRequest){
        try {
            RegistrationResponse registrationResponse = authenticationService.confirmChangePassCode(email, token);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.ACCEPTED.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        }catch (MessagingException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.BAD_GATEWAY.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/change-password")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> processForgotPassword(@RequestParam String email, @RequestParam String password, @RequestParam String confirmPassword, HttpServletRequest httpServletRequest) {
        try {
            if(Objects.equals(password, confirmPassword) && password != null){
                RegistrationResponse registrationResponse = authenticationService.changePassword(email, password);
                GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                        .data(registrationResponse)
                        .status(HttpStatus.ACCEPTED.value())
                        .path(httpServletRequest.getRequestURI())
                        .success(true)
                        .timestamp(Instant.now().toEpochMilli())
                        .build();
                return ResponseEntity.ok(globalResponse);
            }else {
                GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                        .status(HttpStatus.NOT_ACCEPTABLE.value())
                        .path(httpServletRequest.getRequestURI())
                        .errorMessage("Password and Confirm Password should be same.")
                        .success(false)
                        .timestamp(Instant.now().toEpochMilli())
                        .build();
                return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(globalResponse);
            }
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        }catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }


    @RequestMapping(method = RequestMethod.GET, value = "/get-current-logged-in-user")
    public ResponseEntity<GlobalResponse<RegistrationResponse>> getLoggedInUser(HttpServletRequest request) {
        try {
            RegistrationResponse registrationResponse = authenticationService.getLoggedInUser(request);
            GlobalResponse<RegistrationResponse> globalResponse = GlobalResponse.<RegistrationResponse>builder()
                    .data(registrationResponse)
                    .status(HttpStatus.OK.value())
                    .path(request.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (AuthenticationException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .path(request.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (CustomException e) {
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.NOT_ACCEPTABLE.value())
                    .path(request.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errorResponse);
        } catch (RuntimeException e){
            GlobalResponse<RegistrationResponse> errorResponse = GlobalResponse.<RegistrationResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .path(request.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
}
