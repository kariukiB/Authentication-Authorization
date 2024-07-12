package com.kariuki.security.config;

import com.kariuki.security.user.User;
import com.kariuki.security.user.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Optional;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("Authorization header is missing or does not start with Bearer.");
            logAllHeaders(request);
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = authHeader.substring(7);
        System.out.println("JWT Token: " + jwtToken);
        String username = null;

        try {
            Claims claims = jwtService.parseToken(jwtToken);
            if (claims != null) {
                username = claims.getSubject();
                System.out.println("Extracted Username: " + username);
            } else {
                System.out.println("Failed to parse token claims.");
            }
        } catch (Exception e) {
            System.out.println("Failed to extract username from token: " + e.getMessage());
        }

        if (username == null) {
            System.out.println("Username extraction returned null");
            filterChain.doFilter(request, response);
            return;
        }

        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isEmpty()) {
            System.out.println("User not found in repository.");
            filterChain.doFilter(request, response);
            return;
        }

        User user = userOptional.get();
        System.out.println("User found: " + user.getUsername());

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
        System.out.println("Authentication successful for user: " + user.getUsername());

        filterChain.doFilter(request, response);
    }

    private void logAllHeaders(HttpServletRequest request) {
        System.out.println("Logging all request headers:");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            System.out.println(headerName + ": " + headerValue);
        }
    }


}
