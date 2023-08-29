package br.com.glstore.auth.application.controllers;

import br.com.glstore.auth.application.services.AuthenticationService;
import br.com.glstore.auth.infra.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
//@RequestMapping("api/v1/user")
@RequestMapping("api/v1/auth-user")
public class AuthenticationUserController {

    private UserRepository userRepository;
    private final AuthenticationService jwtService;

    @Autowired
    public AuthenticationUserController(UserRepository userRepository, AuthenticationService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }


    @PostMapping("authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request){
        var jwtToken = jwtService.generateToken(request);
        return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
    }

}
