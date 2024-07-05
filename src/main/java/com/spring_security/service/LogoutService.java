package com.spring_security.service;

import com.spring_security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {

        final String authHead = request.getHeader("Authorization");
        final String jwt;

        if(authHead == null || !authHead.startsWith("Bearer ")) {
            return;
        }

        jwt = authHead.substring(7);

        var storedToken = tokenRepository.findByAccessToken(jwt)
                .orElse(null);

        if (storedToken !=null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);

            tokenRepository.save(storedToken);
        }
    }
}
