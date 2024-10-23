package org.ian.springboot3webfluxsecurity.service;

import org.ian.springboot3webfluxsecurity.entity.Role;
import org.ian.springboot3webfluxsecurity.entity.RoleType;
import org.ian.springboot3webfluxsecurity.entity.User;
import org.ian.springboot3webfluxsecurity.repository.RoleRepository;
import org.ian.springboot3webfluxsecurity.repository.UserRepository;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService implements ReactiveUserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.justOrEmpty(userRepository.findByUsername(username));
    }

    @Transactional
    public User saveUser(User user, List<String> roleTypes) {
        user.setPassword(user.getPassword());
        List<RoleType> roleTypeList = roleTypes.stream().map(RoleType::fromString).collect(Collectors.toList());
        Set<Role> existRoles = roleRepository.findByRoleTypeIn(roleTypeList);
        if (existRoles.size() != roleTypes.size()) {
            Set<RoleType> existRoleTypes = existRoles.stream().map(Role::getRoleType).collect(Collectors.toSet());
            List<Role> notExistRoles = roleTypeList.stream()
                    .filter(r -> !existRoleTypes.contains(r)).map(Role::new).collect(Collectors.toList());
            existRoles.addAll(roleRepository.saveAll(notExistRoles));
        }
        user.setRoles(existRoles);
        return userRepository.save(user);
    }

    @Transactional
    public void saveRoles(List<String> roleTypes) {
        Set<Role> roles = roleTypes.stream()
                .map(RoleType::fromString)
                .map(Role::new)
                .collect(Collectors.toSet());
        roleRepository.saveAll(roles);
    }
}
