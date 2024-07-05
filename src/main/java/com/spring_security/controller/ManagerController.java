package com.spring_security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/manager")
@PreAuthorize("hasRole('MANAGER')")
public class ManagerController {

    @GetMapping
    @PreAuthorize("hasAuthority('manager:read')")
    public String get() {
        return "GET:: management controller";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('manager:create')")
    public String post() {
        return "POST:: management controller";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('manager:update')")
    public String put() {
        return "PUT:: management controller";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('manager:delete')")
    public String delete() {
        return "DELETE:: management controller";
    }
}
