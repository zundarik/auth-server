package com.zundarik.auth.server.controller;

import com.zundarik.auth.server.jose.Jwks;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
class JwkSetEndpoint {

    @GetMapping("/oauth/keys")
    @ResponseBody
    public Map<String, Object> getKey() {
        return Jwks.jwkSet().toJSONObject();
    }
}