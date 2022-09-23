package com.zundarik.auth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

@Configuration
public class ProviderSettingsConfig {

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://localhost:8010")
                .authorizationEndpoint("/oauth/authorize")
                .tokenEndpoint("/oauth/token")
                .tokenIntrospectionEndpoint("/oauth/introspect")
                .tokenRevocationEndpoint("/oauth/revoke")
                .jwkSetEndpoint("/oauth/jwks")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcClientRegistrationEndpoint("/connect/register")
                .build();
    }
}
