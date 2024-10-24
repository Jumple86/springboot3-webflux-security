package org.ian.springboot3webfluxsecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class TokenSecurityContextRepository implements ServerSecurityContextRepository {
    private final TokenAuthenticationManager tokenAuthenticationManager;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public TokenSecurityContextRepository(TokenAuthenticationManager tokenAuthenticationManager, ReactiveStringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.defer(() -> Mono.error(new UnsupportedOperationException("No save method")));
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(s -> s.length() > 7 && s.startsWith("Bearer "))
                .flatMap(s -> this.decode(s.substring(7)))
                .onErrorResume(Mono::error)
                .flatMap(auth -> tokenAuthenticationManager.authenticate(auth))
                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid Credentials")))
                .map(SecurityContextImpl::new);
    }

    public Mono<Authentication> decode(String token) {
        return redisTemplate.opsForHash().entries(token)
                .collectMap(entry -> (String) entry.getKey(), Map.Entry::getValue)
                .map(userMap -> {
                    Set<String> roles = this.convertToRoleSet((String) userMap.get("roles"));
                    Set<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
                    return new UsernamePasswordAuthenticationToken(userMap.get("username"), token, authorities);
                });
    }

    private Set<String> convertToRoleSet(String roleString) {
        try {
        Set roles = objectMapper.readValue(roleString, HashSet.class);
        return roles;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
