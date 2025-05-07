package com.example.security_service.controllers;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.security_service.dto.JwtResponse;
import com.example.security_service.dto.LoginRequest;
import com.example.security_service.dto.MessageResponse;
import com.example.security_service.dto.SignupRequest;
import com.example.security_service.models.ERole;
import com.example.security_service.models.Permission;
import com.example.security_service.models.Role;
import com.example.security_service.models.User;
import com.example.security_service.repositories.PermissionRepository;
import com.example.security_service.repositories.RoleRepository;
import com.example.security_service.repositories.UserRepository;
import com.example.security_service.security.jwt.JwtUtils;
import com.example.security_service.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> permissions = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                userDetails.getFirstName(),
                userDetails.getLastName(),
                userDetails.getRole(),
                permissions));
    }

    @GetMapping("/check-permission")
    public Boolean checkPermission(@RequestParam String role,
            @RequestParam String path,
            @RequestParam String method) {
        try {
            // Decode URL path
            String decodedPath = URLDecoder.decode(path, StandardCharsets.UTF_8.name()).trim();

            logger.debug("Checking permission - Role: {}, Path: {}, Method: {}",
                    role, decodedPath, method);

            // Admin role có tất cả quyền
            if ("ROLE_ADMIN".equals(role)) {
                return true;
            }

            // Lấy tất cả permission của role
            List<Permission> permissions = permissionRepository.findByRoleName(role);

            logger.debug("Found {} permissions for role {}", permissions.size(), role);

            // Kiểm tra từng permission xem có khớp với path và method không
            AntPathMatcher pathMatcher = new AntPathMatcher();
            boolean hasPermission = permissions.stream()
                    .anyMatch(permission -> {
                        boolean methodMatch = method.equalsIgnoreCase(permission.getMethod().name());
                        boolean pathMatch = pathMatcher.match(permission.getPath(), decodedPath);

                        logger.debug(
                                "Permission check - Name: {}, Path: {}, Method: {}, MethodMatch: {}, PathMatch: {}",
                                permission.getName(), permission.getPath(), permission.getMethod(), methodMatch,
                                pathMatch);

                        return methodMatch && pathMatch;
                    });

            logger.debug("Permission check result: {}", hasPermission);
            return hasPermission;

        } catch (UnsupportedEncodingException e) {
            logger.error("Error decoding path: {}", e.getMessage());
            return false;
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user account
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setActive(true);

        // Assign role to user
        String strRole = signUpRequest.getRole();
        Role role;

        if (strRole == null) {
            role = roleRepository.findByName(ERole.ROLE_CUSTOMER)
                    .orElseThrow(() -> new RuntimeException("Error: Default role is not found."));
        } else {
            switch (strRole) {
                case "admin":
                    role = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Admin role is not found."));
                    break;
                case "technician":
                    role = roleRepository.findByName(ERole.ROLE_TECHNICIAN)
                            .orElseThrow(() -> new RuntimeException("Error: Technician role is not found."));
                    break;
                default:
                    role = roleRepository.findByName(ERole.ROLE_CUSTOMER)
                            .orElseThrow(() -> new RuntimeException("Error: Customer role is not found."));
            }
        }

        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}