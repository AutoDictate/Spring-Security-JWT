package com.spring_security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @PostMapping
    @PreAuthorize("hasRole('admin:write')")
    public String post() {
        return "POST:: admin controller";
    }

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String get() {
        return "GET:: admin controller";
    }

    @PutMapping
    @PreAuthorize("hasRole('admin:update')")
    public String put() {
        return "PUT:: admin controller";
    }

    @DeleteMapping
    @PreAuthorize("hasRole('admin:delete')")
    public String delete() {
        return "DELETE:: admin controller";
    }
}
