package com.example.api_gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtUtils {

   private final String secret;

    public JwtUtils(@Value("${jwt.secret}") String secret) {
        this.secret = secret;
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(this.secret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isExpired(String token) {
        try {
            return getClaimsFromToken(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public Integer extractUserId(String token) {
        try {
            return Integer.parseInt(getClaimsFromToken(token).getSubject());
        } catch (Exception e) {
            return null;
        }
    }


}
