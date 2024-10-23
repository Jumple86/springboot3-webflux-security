package org.ian.springboot3webfluxsecurity.service;

import org.ian.springboot3webfluxsecurity.entity.User;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;

public class TokenAuthenticationManager implements ReactiveAuthenticationManager {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public TokenAuthenticationManager(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        if (authentication.isAuthenticated()) { return Mono.just(authentication); }
        return Mono.just(authentication)
                .switchIfEmpty(Mono.error(new BadCredentialsException("Bad Credentials")))
                .map(authenticationToken -> authenticationToken.getPrincipal().toString())
                .flatMap(userService::findByUsername)
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found")))
                .filter(u -> passwordEncoder.matches(authentication.getCredentials().toString(), u.getPassword()))
                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid username or password")))
                .cast(User.class)
                .map(u -> new UsernamePasswordAuthenticationToken(u.getUsername(), null, u.getAuthorities()));
    }
}
