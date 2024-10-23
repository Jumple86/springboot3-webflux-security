package org.ian.springboot3webfluxsecurity.entity;

public enum RoleType {
    ROLE_USER,
    ROLE_ADMIN;

    public static RoleType fromString(String type) {
        if ("ROLE_ADMIN".equals(type)) {
            return ROLE_ADMIN;
        } else if ("ROLE_USER".equals(type)) {
            return ROLE_USER;
        } else {
            return null;
        }
    }
}
