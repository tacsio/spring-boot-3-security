package io.tacsio.security.controlers.dto;

public record AuthenticationRequest(
        String email,
        String password) {
}
