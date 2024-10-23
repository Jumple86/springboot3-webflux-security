package org.ian.springboot3webfluxsecurity.controller;

import org.ian.springboot3webfluxsecurity.dto.AuthRequest;
import org.ian.springboot3webfluxsecurity.dto.AuthResponse;
import org.ian.springboot3webfluxsecurity.service.JwtService;
import org.ian.springboot3webfluxsecurity.service.TokenAuthenticationManager;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@RestController
public class UserController {
    private final TokenAuthenticationManager tokenAuthenticationManager;
    private final JwtService jwtService;

    public UserController(TokenAuthenticationManager tokenAuthenticationManager, JwtService jwtService) {
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public Mono<AuthResponse> login(@RequestBody AuthRequest request) {
        return Mono.just(request)
                .flatMap(authRequest -> {
                    Authentication authentication = new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword());
                    return tokenAuthenticationManager.authenticate(authentication);
                })
                .doOnError(e -> new BadCredentialsException("Invalid username or password"))
                .doOnNext(authentication -> ReactiveSecurityContextHolder.withAuthentication(authentication))
                .map(authentication -> new AuthResponse(jwtService.generateToken((String) authentication.getPrincipal())));
    }
}
