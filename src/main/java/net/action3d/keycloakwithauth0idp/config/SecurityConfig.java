package net.action3d.keycloakwithauth0idp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.base-url}")
    private String appBaseUrl;

    @Value("${app.port}")
    private String appPort;

    @Value("${app.path}")
    private String contextPath;

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/tokens").authenticated()
                        .anyRequest().permitAll()
                )
                // Add this headers configuration
                .headers(headers -> headers
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000) // 1 year in seconds
                        )
                        // Optional: Add other security headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
                        )
                        .frameOptions(frame -> frame
                                .sameOrigin()
                        )
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/oauth2/authorization/keycloak")
                        .defaultSuccessUrl("/tokens", true)
                        .redirectionEndpoint()
                        .baseUri("/login/oauth2/code/keycloak")
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(keycloakLogoutHandler())
                        .logoutSuccessUrl(contextPath)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .oauth2Client();

        return http.build();
    }

    private LogoutHandler keycloakLogoutHandler() {
        return (request, response, authentication) -> {
            try {
                if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
                    OidcUser user = (OidcUser) authentication.getPrincipal();

                    String logoutUrl = UriComponentsBuilder.fromHttpUrl(keycloakBaseUrl)
                            .path("/realms/{realm}/protocol/openid-connect/logout")
                            .queryParam("id_token_hint", user.getIdToken().getTokenValue())
                            .queryParam("post_logout_redirect_uri", appBaseUrl + ":" + appPort+ contextPath)
                            .queryParam("client_id", clientId)
                            .buildAndExpand(keycloakRealm)
                            .toUriString();

                    response.sendRedirect(logoutUrl);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to logout from Keycloak", e);
            }
        };
    }
}