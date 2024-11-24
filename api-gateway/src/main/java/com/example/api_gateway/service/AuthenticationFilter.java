package com.example.api_gateway.service;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final RouterValidator routerValidator;
    private final JwtUtils jwtUtils;

    public AuthenticationFilter(RouterValidator routerValidator, JwtUtils jwtUtils) {
        super(Config.class);
        this.routerValidator = routerValidator;
        this.jwtUtils = jwtUtils;
    }

    public static class Config {
        // Put configuration properties here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            var request = exchange.getRequest();

            ServerHttpRequest httpRequest = null;

            if (routerValidator.isSecured.test(request)) {
                // Validate the token
                if (authMissing(request)) {
                    return onError(exchange, "Authorization header is missing in request");
                }

                String authHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

                if (!authHeader.startsWith("Bearer ")) {
                    return onError(exchange, "Authorization header is invalid");
                }

                String token = authHeader.substring(7);

                if (jwtUtils.isExpired(token)) {
                    return onError(exchange, "Token has expired");
                }

                httpRequest = exchange.getRequest().mutate()
                        .header("x-userId", jwtUtils.extractUserId(token).toString())
                        .build();

            }

            return chain.filter(exchange.mutate().request(httpRequest).build());
        };
    }

     private Mono<Void> onError(ServerWebExchange exchange, String err) {
         ServerHttpResponse response = exchange.getResponse();
         response.setStatusCode(HttpStatus.UNAUTHORIZED);
         return response.setComplete();
     }

     private boolean authMissing(org.springframework.http.server.reactive.ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
     }
}
