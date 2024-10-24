package org.ian.springboot3webfluxsecurity.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.ian.springboot3webfluxsecurity.dto.AuthRequest;
import org.ian.springboot3webfluxsecurity.dto.AuthResponse;
import org.ian.springboot3webfluxsecurity.dto.GreetResponse;
import org.ian.springboot3webfluxsecurity.dto.UserDTO;
import org.ian.springboot3webfluxsecurity.entity.User;
import org.ian.springboot3webfluxsecurity.service.TokenAuthenticationManager;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
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

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
public class UserController {
    private final TokenAuthenticationManager tokenAuthenticationManager;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public UserController(TokenAuthenticationManager tokenAuthenticationManager,
                          ReactiveStringRedisTemplate redisTemplate,
                          ObjectMapper objectMapper) {
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
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
                .zipWith(Mono.just(UUID.randomUUID().toString().replaceAll("-", "")))
                .flatMap(tuple -> redisTemplate.opsForHash().putAll(tuple.getT2(), this.convertToMap((User) tuple.getT1().getCredentials()))
                        .flatMap(x -> redisTemplate.expire(tuple.getT2(), Duration.ofMinutes(30)))
                        .map(x -> tuple.getT2())
                )
                .map(token -> new AuthResponse(token));
    }

    @SneakyThrows
    private Map<String, String> convertToMap(User user) {
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setUsername(user.getUsername());
        userDTO.setPassword(user.getPassword());
        userDTO.setRoles(user.getRoles().stream().map(role -> role.getRoleType().name()).collect(Collectors.toSet()));

        Map<String, Object> objectMap = objectMapper.convertValue(userDTO, new TypeReference<Map<String, Object>>() {});

        Map<String, String> stringMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : objectMap.entrySet()) {
            if (entry.getValue() instanceof String) {
                stringMap.put(entry.getKey(), (String) entry.getValue());
            } else {
                // 將非字串類型轉換為 JSON 字串
                stringMap.put(entry.getKey(), objectMapper.writeValueAsString(entry.getValue()));
            }
        }

        return stringMap;
    }

    @GetMapping("/admin")
    public Mono<GreetResponse> admin() {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(this::getCurrentUsername)
                .map(username -> new GreetResponse("Hello " + username));
    }

    @GetMapping("/user")
    public Mono<GreetResponse> user() {
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
