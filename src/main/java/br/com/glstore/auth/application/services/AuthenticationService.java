package br.com.glstore.auth.application.services;

import br.com.glstore.auth.application.controllers.AuthenticationRequest;
import br.com.glstore.auth.domain.entities.Token;
import br.com.glstore.auth.domain.entities.User;
import br.com.glstore.auth.infra.repositories.TokenRepository;
import br.com.glstore.auth.infra.repositories.UserRepository;
import br.com.glstore.auth.infra.security.jwt.JwtService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;

    public AuthenticationService(UserRepository userRepository, TokenRepository tokenRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.jwtService = jwtService;
    }

    public String generateToken(AuthenticationRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (!validateUser(user, request)) {
            throw new AuthenticationCredentialsNotFoundException("Username or Password invalid");
        }

        if (CollectionUtils.isEmpty(user.getTokens()) || user.getTokens().stream().allMatch(tkn -> tkn.isExpired() && tkn.isRevoked())) {
            revokeAllUserTokens(user);
            String jwtToken = jwtService.generateToken(user);
            saveUserToken(user, jwtToken);
            return jwtToken;
        } else if (user.getTokens().stream().anyMatch(tkn -> !tkn.isExpired() && !tkn.isRevoked())) {
            return user.getTokens().stream().filter(tkn -> !tkn.isExpired() && !tkn.isRevoked()).collect(Collectors.toList()).get(0).getToken();
        }

        return jwtService.generateToken(user);
    }

    public boolean validateUser(User user, AuthenticationRequest request) {
        return user != null && user.isMatchUserName(request.getUserName())
                && user.isMatchPassword(request.getPassword());
    }

    public void saveUserToken(User user, String token){
        Token tokenEntity = new Token(token, user, false, false);
        tokenRepository.save(tokenEntity);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty()){
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
