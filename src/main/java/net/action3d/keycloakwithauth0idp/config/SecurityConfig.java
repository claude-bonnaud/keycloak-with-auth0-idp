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

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String appRedirectUri = appBaseUrl + ":" + appPort;

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/tokens").authenticated()
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/tokens", true)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(keycloakLogoutHandler())
                        .logoutSuccessUrl(appRedirectUri)
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
                            .queryParam("post_logout_redirect_uri", appBaseUrl + ":" + appPort)
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