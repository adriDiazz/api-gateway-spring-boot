package com.example.api_gateway.service;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Predicate;

@Service
public class RouterValidator {
    public static final List<String> openedEndpoints = List.of("/v1/api/auth");

    public Predicate<ServerHttpRequest> isSecured = request -> openedEndpoints.stream()
            .noneMatch(uri -> request.getURI().getPath().contains(uri));
}
