package org.ian.springboot3webfluxsecurity.dto;

import lombok.Data;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Data
public class UserDTO implements Serializable {
    private Integer id;
    private String username;
    private String password;
    private Set<String> roles = new HashSet<>();
}
