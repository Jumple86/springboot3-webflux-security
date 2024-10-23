package org.ian.springboot3webfluxsecurity.config;

import org.ian.springboot3webfluxsecurity.service.TokenAuthenticationManager;
import org.ian.springboot3webfluxsecurity.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    private final UserService userService;

    public SecurityConfig(UserService userService) {
        this.userService = userService;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(authorizeExchange -> authorizeExchange.pathMatchers("/login").permitAll())
                .addFilterAt(authenticationWebFilter(tokenAuthenticationManager()), SecurityWebFiltersOrder.AUTHORIZATION)
                .build();
    }

    @Bean
    public AuthenticationWebFilter authenticationWebFilter(TokenAuthenticationManager tokenAuthenticationManager) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(tokenAuthenticationManager);

        return authenticationWebFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationManager tokenAuthenticationManager() {
        return new TokenAuthenticationManager(userService, passwordEncoder());
    }
}
