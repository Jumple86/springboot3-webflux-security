package org.ian.springboot3webfluxsecurity;

import org.ian.springboot3webfluxsecurity.entity.User;
import org.ian.springboot3webfluxsecurity.service.UserService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class Springboot3WebfluxSecurityApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(Springboot3WebfluxSecurityApplication.class, args);
        UserService userService = context.getBean(UserService.class);
        List<String> roles = Arrays.asList("ROLE_ADMIN", "ROLE_USER");
        userService.saveRoles(roles);
        userService.saveUser(new User("admin", "{noop}admin"), roles);
    }

}
