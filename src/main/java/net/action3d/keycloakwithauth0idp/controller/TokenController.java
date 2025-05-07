package net.action3d.keycloakwithauth0idp.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class TokenController {

    @Value("${app.base-url}")
    private String appBaseUrl;

    @Value("${app.port}")
    private String appPort;

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${auth0.domain}")
    private String auth0Domain;

    @Value("${auth0.client-id}")
    private String auth0ClientId;

    @GetMapping("/tokens")
    public String showTokens(
            @AuthenticationPrincipal OidcUser user,
            @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient,
            Model model) {

        if (user != null) {
            model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
            model.addAttribute("refreshToken", authorizedClient.getRefreshToken() != null ?
                    authorizedClient.getRefreshToken().getTokenValue() : "Not available");
            model.addAttribute("claims", user.getClaims());
            model.addAttribute("serverPort", appPort);
        }
        return "tokens";
    }

    @PostMapping("/logout")
    public String logout(
            HttpServletRequest request,
            @AuthenticationPrincipal OidcUser user) throws Exception {

        // 1. Local logout
        request.logout();

        // 2. Prepare URLs
        String baseUrl = appBaseUrl + ":" + appPort;
        String encodedBaseUrl = URLEncoder.encode(baseUrl, StandardCharsets.UTF_8);

        // 3. Keycloak logout URL (will be used as returnTo for Auth0)
        String keycloakLogoutUrl = keycloakBaseUrl + "/realms/" + keycloakRealm +
                "/protocol/openid-connect/logout" +
                "?id_token_hint=" + user.getIdToken().getTokenValue() +
                "&post_logout_redirect_uri=" + encodedBaseUrl;

        // 4. Auth0 logout URL (primary logout endpoint)
        String auth0LogoutUrl = "https://dev-qdejy8uzphouw6cj.us.auth0.com/oidc/logout" +
                "?client_id=" + auth0ClientId +  // Add this to application.yml
                "&returnTo=" + URLEncoder.encode(keycloakLogoutUrl, StandardCharsets.UTF_8);

        return "redirect:" + auth0LogoutUrl;
    }
}