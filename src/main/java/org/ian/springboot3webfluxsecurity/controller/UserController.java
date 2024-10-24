package org.ian.springboot3webfluxsecurity.controller;

import org.ian.springboot3webfluxsecurity.dto.AuthRequest;
import org.ian.springboot3webfluxsecurity.dto.AuthResponse;
import org.ian.springboot3webfluxsecurity.dto.GreetResponse;
import org.ian.springboot3webfluxsecurity.service.JwtService;
import org.ian.springboot3webfluxsecurity.service.TokenAuthenticationManager;
import org.ian.springboot3webfluxsecurity.service.UserService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Objects;

@RestController
public class UserController {
    private final TokenAuthenticationManager tokenAuthenticationManager;
    private final JwtService jwtService;
    private final UserService userService;

    public UserController(TokenAuthenticationManager tokenAuthenticationManager, JwtService jwtService, UserService userService) {
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.jwtService = jwtService;
        this.userService = userService;
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
                .map(authentication -> new AuthResponse(jwtService.generateToken((String) authentication.getPrincipal(), authentication.getAuthorities())));
    }

    @GetMapping("/admin")
    public Mono<GreetResponse> admin() {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(this::getCurrentUsername)
                .map(username -> new GreetResponse("Hello " + username));
    }

    private Mono<String> getCurrentUsername(SecurityContext securityContext) {
        return Mono.justOrEmpty(securityContext.getAuthentication()).filter(Objects::nonNull)
                .map(authentication -> authentication.getPrincipal()).filter(Objects::nonNull)
                .map(o -> o.toString());
    }
}
