package com.ojha.Auth_Server.auth;

import com.ojha.Auth_Server.session.GeneralSessionRepository;
import com.ojha.Auth_Server.session.Session;
import com.ojha.Auth_Server.session.SessionService;
import com.ojha.Auth_Server.Token.GeneralTokenRepository;
import com.ojha.Auth_Server.Token.Token;
import com.ojha.Auth_Server.Token.TokenType;
import com.ojha.Auth_Server.email.EmailService;
import com.ojha.Auth_Server.email.EmailTemplateName;
import com.ojha.Auth_Server.handler.CustomException;
import com.ojha.Auth_Server.role.GeneralRoleRepository;
import com.ojha.Auth_Server.security.JwtService;
import com.ojha.Auth_Server.user.*;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final GeneralRoleRepository generalRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final GeneralUserRepository generalUserRepository;
    private final GeneralTokenRepository generalTokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SessionService sessionService;
    private final GeneralSessionRepository generalSessionRepository;
    @Value("${application.security.jwt.expiration}")
    private Long JWT_TOKEN_EXPIRE_IN;
    @Value("${application.security.OTP.expiration}")
    private Long OTP_EXPIRE_IN;


    public RegistrationResponse register(RegistrationRequest request) throws MessagingException {
        try {
            if (generalUserRepository.findByEmail(request.getEmail()).isPresent()){
                throw new CustomException("Email already in use, try with another email.");
            }else {
                var userRole = generalRoleRepository.findByName("ADMIN")
                        .orElseThrow(() -> new CustomException("ROLE was not initialized, Contact to admin."));
                var user = User.builder()
                        .email(request.getEmail())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .accountLocked(false)
                        .enabled(false)
                        .firstLogin(true)
                        .roles(List.of(userRole))
                        .build();
                generalUserRepository.save(user);
                sendValidationEmail(user);

                return RegistrationResponse.builder()
                        .userEmail(user.getUsername())
                        .role(user.getAuthorities().toString())
                        .build();
            }
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

    private void sendValidationEmail(User user) throws MessagingException {
        try {
            var newToken = generateAndSaveActivationToken(user);
            emailService.sendEmail(
                    user.getEmail(),
                    user.getEmail(),
                    EmailTemplateName.ACTIVATE_ACCOUNT,
                    newToken,
                    "Account Activation"
            );
        }catch (CustomException e){
            throw new CustomException("Not able to send activation email");
        }
    }

    private String generateAndSaveActivationToken(User user) {
        try {
            String generatedToken = generateActivationCode(6);
            var token = Token.builder()
                    .token(generatedToken)
                    .tokenType(TokenType.FIRST_VERIFY.value)
                    .createdAt(Instant.now().toEpochMilli())
                    .expiresAt(Instant.now().toEpochMilli() + OTP_EXPIRE_IN)
                    .user(user)
                    .build();
            generalTokenRepository.save(token);
            return generatedToken;
        }catch (CustomException e){
            throw new CustomException("Not able to generate activation token");
        }
    }

    public String generateActivationCode(int length) {
        try {
            String characters = "0123456789";
            StringBuilder codeBuilder = new StringBuilder();
            SecureRandom secureRandom = new SecureRandom();
            for(int i = 0; i < length; i++){
                int randomIndex = secureRandom.nextInt(characters.length());
                codeBuilder.append(characters.charAt(randomIndex));
            }
            return codeBuilder.toString();
        }catch (CustomException e){
            throw new CustomException("Not able to generate activation code");
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws AuthenticationException, MessagingException {
        try {
            System.out.println("User in request: " + request.getEmail());
            if(generalUserRepository.findUserByEmail(request.getEmail()) == null){
                throw new CustomException("Bad credentials");
            }

            User requestUser = generalUserRepository.findUserByEmail(request.getEmail());
            if (!requestUser.isEnabled()) {
                sendValidationEmail(requestUser);
                throw new CustomException("Email not verified. A token has been sent to the same email address.");
            }

            var auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = (User) auth.getPrincipal();
            var claims = new HashMap<String, Object>();
            String sessionId;
            String existingSessionId = sessionService.findSessionIdByEmail(user.getUsername());

            if(existingSessionId == null){
                Session session = sessionService.createSessionId(user.getUsername());
                sessionId = session.getSessionId();
            }else {
                Session session = generalSessionRepository.findBySessionId(existingSessionId).get();
                if(session.getExpiresAt().compareTo(Instant.now().toEpochMilli()) < 0) {
                    session.setValid(false);
                    generalSessionRepository.save(session);
                    Session session1 = sessionService.createSessionId(user.getUsername());
                    sessionId = session1.getSessionId();
                }else {
                    sessionId = existingSessionId;
                }
            }

            claims.put("email", user.getUsername());
            claims.put("session_id", sessionId);
            String jwtToken = jwtService.generateToken(claims, user);

            return AuthenticationResponse.builder()
                    .userEmail(user.getUsername())
                    .accessToken(jwtToken)
                    .sessionId(sessionId)
                    .role(user.getAuthorities().toString())
                    .firstLogin(user.isFirstLogin())
                    .tokenType("Bearer")
                    .expiresIn(Instant.now().toEpochMilli() + JWT_TOKEN_EXPIRE_IN)
                    .build();
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

    public RegistrationResponse activateAccount(String email, String token) throws MessagingException {
        try {
            Token savedToken = generalTokenRepository.findByToken(token)
                    .orElseThrow(() -> new CustomException("Invalid or expired token"));
            if(((Instant.now().toEpochMilli()) - OTP_EXPIRE_IN) > (savedToken.getExpiresAt())){
                sendValidationEmail(savedToken.getUser());
                throw new CustomException("Activation token has been expired. A new token has been sent to the same email address.");
            }

            if(Objects.equals(savedToken.getTokenType(), TokenType.FIRST_VERIFY.value)){
                var user = generalUserRepository.findById(savedToken.getUser().getId())
                        .orElseThrow(() -> new CustomException("Invalid or expired token"));
                if(!Objects.equals(user.getEmail(), email)){
                    throw new CustomException("Invalid or expired token");
                }
                if(!(savedToken.getValidatedAt() == null)){
                    throw new CustomException("Invalid or expired token");
                }
                user.setEnabled(true);
                generalUserRepository.save(user);
                savedToken.setValidatedAt(Instant.now().toEpochMilli());
                generalTokenRepository.save(savedToken);

                return RegistrationResponse.builder()
                        .userEmail(user.getUsername())
                        .role(user.getAuthorities().toString())
                        .build();

            }else {
                throw new CustomException("Invalid or expired token");
            }
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }


    //    Change password
    public RegistrationResponse sendChangePassOTP(String email) throws MessagingException {
        try {
            if (generalUserRepository.findByEmail(email).isPresent()){
                User user = generalUserRepository.findUserByEmail(email);
                sendChangePassEmail(email);
                return RegistrationResponse.builder()
                        .userEmail(user.getUsername())
                        .role(user.getAuthorities().toString())
                        .build();
            }else {
                throw new CustomException("Invalid Email");
            }
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

    private void sendChangePassEmail(String email) throws MessagingException {
        try {
            var newToken = generateAndSaveChangePassToken(email);
            emailService.sendEmail(
                    email,
                    email,
                    EmailTemplateName.Change_PASSWORD,
                    newToken,
                    "Change Password"
            );
        }catch (CustomException e){
            throw new CustomException("Not able to send change password email");
        }
    }

    private String generateAndSaveChangePassToken(String email) {
        try {
            User user = generalUserRepository.findUserByEmail(email);
            String generatedToken = generateActivationCode(6);
            var token = Token.builder()
                    .token(generatedToken)
                    .tokenType(TokenType.Change_PWD.value)
                    .createdAt(Instant.now().toEpochMilli())
                    .expiresAt(Instant.now().toEpochMilli() + OTP_EXPIRE_IN)
                    .user(user)
                    .build();
            generalTokenRepository.save(token);
            return generatedToken;
        }catch (CustomException e){
            throw new CustomException("Not able to generate and save change password token");
        }
    }


    public RegistrationResponse confirmChangePassCode(String email, String token) throws MessagingException {
        try {
            Token savedToken = generalTokenRepository.findByToken(token)
                    .orElseThrow(() -> new CustomException("Invalid or expired token"));
            if(((Instant.now().toEpochMilli()) - OTP_EXPIRE_IN) > (savedToken.getExpiresAt())){
                sendValidationEmail(savedToken.getUser());
                throw new CustomException("Change Password token has been expired. A new token has been sent to the same email address.");
            }
            if(!Objects.equals(savedToken.getUser().getEmail(), email)){
                throw new CustomException("Invalid or expired token");
            }

            if(Objects.equals(savedToken.getTokenType(), TokenType.Change_PWD.value)){
                if(!(savedToken.getValidatedAt() == null)){
                    throw new CustomException("Invalid or expired token");
                }
                savedToken.setValidatedAt(Instant.now().toEpochMilli());
                generalTokenRepository.save(savedToken);

                return RegistrationResponse.builder()
                        .userEmail(savedToken.getUser().getEmail())
                        .role(savedToken.getUser().getAuthorities().toString())
                        .build();
            }else {
                throw new CustomException("Invalid or expired token");
            }
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }


    public RegistrationResponse changePassword(String email, String password) {
        try {
            if (generalUserRepository.findByEmail(email).isEmpty()){
                throw new CustomException("Email not found");
            }
            var user = generalUserRepository.findByEmail(email)
                    .orElseThrow(() -> new CustomException("Email not found"));
            user.setPassword(passwordEncoder.encode(password));
            user.setFirstLogin(false);
            generalUserRepository.save(user);

            return RegistrationResponse.builder()
                    .userEmail(user.getEmail())
                    .role(user.getAuthorities().toString())
                    .build();
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }


    public RegistrationResponse getLoggedInUser(HttpServletRequest request) {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String token = authorizationHeader.substring(7); // Remove "Bearer " prefix
                try {
                    String user = jwtService.extractUsername(token);
                    if(user != null) {
                        User userDetails = generalUserRepository.findUserByEmail(user);
                        if(userDetails != null) {
                            return RegistrationResponse.builder()
                                    .userEmail(userDetails.getUsername())
                                    .role(userDetails.getAuthorities().toString())
                                    .build();
                        }
                    }
                } catch (Exception e) {
                    throw new CustomException("Invalid or expired token");
                }
            }
            throw new CustomException("Invalid or expired token");
        }catch (CustomException e){
            throw new CustomException(e.getMessage());
        }
    }

}
