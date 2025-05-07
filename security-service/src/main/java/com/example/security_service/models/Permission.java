package com.example.security_service.models;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "permissions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name;
    
    @Column(nullable = false)
    private String path;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private HttpMethod method;
    
    @Column
    private String description;
    
    public enum HttpMethod {
        GET, POST, PUT, DELETE, PATCH
    }

    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles = new HashSet<>();
}