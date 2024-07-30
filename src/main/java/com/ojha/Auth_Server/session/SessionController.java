package com.ojha.Auth_Server.session;

import com.ojha.Auth_Server.auth.AuthenticationResponse;
import com.ojha.Auth_Server.constants.GlobalResponse;
import com.ojha.Auth_Server.handler.CustomException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/session")
@Tag(name = "Session")
public class SessionController {

    private final SessionService sessionService;

    @RequestMapping(method = RequestMethod.POST, value = "/")
    public ResponseEntity<GlobalResponse<AuthenticationResponse>> session(@RequestBody SessionRequestDto sessionRequestDto, HttpServletRequest httpServletRequest) {
        try {
            AuthenticationResponse authenticationResponse = sessionService.verifySessionId(sessionRequestDto.getSessionId(), sessionRequestDto.getEmail(), httpServletRequest);
            GlobalResponse<AuthenticationResponse> globalResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .data(authenticationResponse)
                    .status(HttpStatus.OK.value())
                    .path(httpServletRequest.getRequestURI())
                    .success(true)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.ok(globalResponse);
        } catch (CustomException e) {
            GlobalResponse<AuthenticationResponse> errorResponse = GlobalResponse.<AuthenticationResponse>builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .path(httpServletRequest.getRequestURI())
                    .errorMessage(e.getMessage())
                    .success(false)
                    .timestamp(Instant.now().toEpochMilli())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
}
