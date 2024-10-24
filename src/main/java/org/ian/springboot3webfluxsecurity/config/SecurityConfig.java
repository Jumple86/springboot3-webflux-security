package org.ian.springboot3webfluxsecurity.config;

import org.ian.springboot3webfluxsecurity.service.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    private final UserService userService;
    private final JwtService jwtService;

    public SecurityConfig(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(authorizeExchange -> authorizeExchange.pathMatchers("/login").permitAll()
                        .pathMatchers("/admin/**").hasRole("ADMIN")
                        .anyExchange().access(this.tokenAuthorizationManager())
                )
                .addFilterAt(authenticationWebFilter(tokenAuthenticationManager()), SecurityWebFiltersOrder.AUTHORIZATION)
                .securityContextRepository(this.serverSecurityContextRepository())
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

    @Bean
    public ServerSecurityContextRepository serverSecurityContextRepository() {
        return new TokenSecurityContextRepository(tokenAuthenticationManager(), jwtService);
    }

    @Bean
    public TokenAuthorizationManager tokenAuthorizationManager() {
        return new TokenAuthorizationManager();
    }
}
