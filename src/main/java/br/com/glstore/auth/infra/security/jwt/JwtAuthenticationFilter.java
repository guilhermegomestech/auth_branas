package br.com.glstore.auth.infra.security.jwt;

import br.com.glstore.auth.infra.repositories.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService, TokenRepository tokenRepository) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.tokenRepository = tokenRepository;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (notWasHeaderAuthorization(request) && request.getServletPath().contains("api/v1/auth-user")) {
            responseDoFilter(request, response, filterChain);
            return;
        }

        if(notWasHeaderAuthorization(request)){
            response.sendError(401, "user not authenticated");
            responseDoFilter(request, response, filterChain);
            return;
        }

        final String jwtToken;
        final String userEmail;
        final String authHeader = request.getHeader("Authorization");
        jwtToken = authHeader.substring(7);

        userEmail = jwtService.extractUsername(jwtToken);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = jwtService.isTokenValid(jwtToken, userDetails);
            if (isTokenValid) {
                authenticationUser(userDetails, request);
            } else {
                final String jwtRefreshToken = jwtService.generateRefreshToken(userDetails);
                authenticationUser(userDetails, request);
            }
        }
        responseDoFilter(request, response, filterChain);
    }

    private void authenticationUser(UserDetails userDetails, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private boolean notWasHeaderAuthorization(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        return authHeader == null || !authHeader.startsWith("Bearer ");
    }

    private void responseDoFilter(HttpServletRequest request, HttpServletResponse response,FilterChain filterChain) throws ServletException, IOException {
        filterChain.doFilter(request, response);
    }
}
