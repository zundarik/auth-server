/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.zundarik.auth.server.config;

import com.zundarik.auth.server.repository.JpaRegisteredClientRepository;
import com.zundarik.auth.server.service.JpaOAuth2AuthorizationConsentService;
import com.zundarik.auth.server.service.JpaOAuth2AuthorizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

//https://spring.io/projects/spring-authorization-server
//https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

	private final JpaRegisteredClientRepository registeredClientRepository;
	private final JpaOAuth2AuthorizationService authorizationService;
	private final JpaOAuth2AuthorizationConsentService authorizationConsentService;
	private final ProviderSettings providerSettings;
	private final OAuth2TokenGenerator<?> tokenGenerator;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		authorizationServerConfigurer
				.registeredClientRepository(registeredClientRepository)
				.authorizationService(authorizationService)
				.authorizationConsentService(authorizationConsentService)
				.providerSettings(providerSettings)
				.tokenGenerator(tokenGenerator)
//				.clientAuthentication(clientAuthentication ->
//						clientAuthentication
//								.authenticationConverter(authenticationConverter)
//								.authenticationProvider(authenticationProvider)
//								.authenticationSuccessHandler(authenticationSuccessHandler)
//								.errorResponseHandler(errorResponseHandler)
//				)
//				.authorizationEndpoint(authorizationEndpoint ->
//						authorizationEndpoint
//								.authorizationRequestConverter(authorizationRequestConverter)
//								.authenticationProvider(authenticationProvider)
//								.authorizationResponseHandler(authorizationResponseHandler)
//								.errorResponseHandler(errorResponseHandler)
//								.consentPage("/oauth2/v1/authorize")
//				)
//				.tokenEndpoint(tokenEndpoint ->
//						tokenEndpoint
//								.accessTokenRequestConverter(accessTokenRequestConverter)
//								.authenticationProvider(authenticationProvider)
//								.accessTokenResponseHandler(accessTokenResponseHandler)
//								.errorResponseHandler(errorResponseHandler)
//				)
//				.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint ->
//						tokenIntrospectionEndpoint
//								.introspectionRequestConverter(introspectionRequestConverter)
//								.authenticationProvider(authenticationProvider)
//								.introspectionResponseHandler(introspectionResponseHandler)
//								.errorResponseHandler(errorResponseHandler)
//				)
//				.tokenRevocationEndpoint(tokenRevocationEndpoint ->
//						tokenRevocationEndpoint
//								.revocationRequestConverter(revocationRequestConverter)
//								.authenticationProvider(authenticationProvider)
//								.revocationResponseHandler(revocationResponseHandler)
//								.errorResponseHandler(errorResponseHandler)
//				)
//				.oidc(oidc ->
//						oidc
//								.userInfoEndpoint(userInfoEndpoint ->
//										userInfoEndpoint.userInfoMapper(userInfoMapper)
//								)
//								.clientRegistrationEndpoint(Customizer.withDefaults())
//				)
		;

		// @formatter:off
		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
					authorizeRequests
							.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.apply(authorizationServerConfigurer);
		// @formatter:on
		return http.build();
	}

}
