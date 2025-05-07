package com.example.security_service.dto;

import lombok.Data;

@Data
public class PermissionCheckRequest {
    private String role;
    private String path;
    private String method;
}
