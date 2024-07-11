package com.spring_security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring_security.model.Token;
import com.spring_security.model.TokenType;
import com.spring_security.model.User;
import com.spring_security.repository.TokenRepository;
import com.spring_security.repository.UserRepository;
import com.spring_security.dto.request.AuthRequest;
import com.spring_security.dto.reponse.AuthenticationResponse;
import com.spring_security.dto.request.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final TokenRepository tokenRepository;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        var savedUser = userRepository.save(user);

        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        saveUserToken(savedUser, accessToken, refreshToken);

        return AuthenticationResponse
                .builder()
                .accessTokens(accessToken)
                .refreshTokens(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(()-> new UsernameNotFoundException("User Not found"));

        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        revokeAllUserTokens(user);
        saveUserToken(user, accessToken, refreshToken);
        return AuthenticationResponse
                .builder()
                .accessTokens(accessToken)
                .refreshTokens(refreshToken)
                .build();
    }

    public void generateRefreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String userEmail;
        final String token;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        token = authHeader.substring(7);
        userEmail = jwtService.extractUserName(token);

        if(userEmail != null) {

            var user = userRepository.findByEmail(userEmail)
                    .orElse(null);
            if(jwtService.isTokenValid(token, user)){

                var accessToken = jwtService.generateToken(user);
                var refreshToken = jwtService.generateRefreshToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken, refreshToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessTokens(accessToken)
                        .refreshTokens(refreshToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);

            }

        }
    }

    private void revokeAllUserTokens(User user) {

        var validUserAccessTokens = tokenRepository.findAllUserAccessTokens(user.getId());
        if(validUserAccessTokens.isEmpty()) {
            return;
        }
        validUserAccessTokens.forEach(
                t-> {
                    t.setRevoked(true);
                    t.setExpired(true);
                }
        );

        tokenRepository.saveAll(validUserAccessTokens);
    }

    private void saveUserToken(User user, String accessToken, String refreshToken) {
        var token = Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(user)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }
}

