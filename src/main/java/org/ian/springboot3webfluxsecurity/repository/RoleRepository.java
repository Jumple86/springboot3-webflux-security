package org.ian.springboot3webfluxsecurity.repository;

import org.ian.springboot3webfluxsecurity.entity.Role;
import org.ian.springboot3webfluxsecurity.entity.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleType(RoleType roleType);

    Set<Role> findByRoleTypeIn(List<RoleType> roleTypes);
}
