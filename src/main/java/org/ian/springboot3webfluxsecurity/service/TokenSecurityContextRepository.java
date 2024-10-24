package org.ian.springboot3webfluxsecurity.service;

import io.jsonwebtoken.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

public class TokenSecurityContextRepository implements ServerSecurityContextRepository {
    private final TokenAuthenticationManager tokenAuthenticationManager;
    private final JwtService jwtService;

    private final static String PAYLOAD_ROLES = "roles";

    public TokenSecurityContextRepository(TokenAuthenticationManager tokenAuthenticationManager, JwtService jwtService) {
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.defer(() -> Mono.error(new UnsupportedOperationException("No save method")));
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(s -> s.length() > 7 && s.startsWith("Bearer "))
                .map(s -> this.decode(s.substring(7)))
                .onErrorResume(Mono::error)
                .flatMap(auth -> tokenAuthenticationManager.authenticate(auth))
                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid Credentials")))
                .map(SecurityContextImpl::new);
    }

    public Authentication decode(String token) {
        Claims claims;
        try {
            claims = jwtService.extractAllClaims(token);
        } catch (ExpiredJwtException e) {
            throw new BadCredentialsException("Expired token");
        } catch (UnsupportedJwtException e) {
            throw new BadCredentialsException("Unsupported token");
        } catch (MalformedJwtException e) {
            throw new BadCredentialsException("Malformed token");
        } catch (SignatureException | IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid token");
        }
        List<String> roles = (List<String>)claims.get(PAYLOAD_ROLES, List.class);
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(claims.getSubject(), token, authorities);
    }
}
