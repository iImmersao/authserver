package com.iimmersao.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfiguration {

    @Autowired
    AuthorizationServerProperties authorizationServerProperties;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> registeredClients = new ArrayList<>();

        System.out.println("************************************");
        System.out.println("Got config:");
        System.out.println(authorizationServerProperties.toString());
        System.out.println("************************************");
        Map<String, AuthorizationServerProperties.Client> clientConfigs = authorizationServerProperties.getClient();
        for (var entry : clientConfigs.entrySet()) {
            Registration r = entry.getValue().getRegistration();
            RegisteredClient rC = getRegisteredClient(r);
            registeredClients.add(rC);
        }

        return new InMemoryRegisteredClientRepository(registeredClients);
    }

    private RegisteredClient getRegisteredClient(Registration clientConfigProperties) {
        //ConfigProperties clientConfig = new ConfigProperties();
        System.out.println("**********************************");
        System.out.println("Retrieved the client config:");
        System.out.println(clientConfigProperties.toString());
        System.out.println("**********************************");

        RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString());

        System.out.println("Adding clientId: " + clientConfigProperties.getClientId());
        registeredClientBuilder.clientId(clientConfigProperties.getClientId());

        System.out.println("Adding client secret: " + clientConfigProperties.getClientSecret());
        registeredClientBuilder.clientSecret(clientConfigProperties.getClientSecret());

        for (String authMethod : clientConfigProperties.getClientAuthenticationMethods()) {
            System.out.println("Adding auth method: " + authMethod);
            ClientAuthenticationMethod method = new ClientAuthenticationMethod(authMethod);
            System.out.println("Adding created auth method: " + method);
            registeredClientBuilder.clientAuthenticationMethod(method);
            if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {
                System.out.println("Method was CLIENT_SECRET_BASIC");
            }
        }

        for (String grantType : clientConfigProperties.getAuthorizationGrantTypes()) {
            System.out.println("Adding auth grant type: " + grantType);
            AuthorizationGrantType grant = new AuthorizationGrantType(grantType);
            System.out.println("Adding created auth grant type: " + grant);
            registeredClientBuilder.authorizationGrantType(grant);
        }

        for (String redirectUri : clientConfigProperties.getRedirectUris()) {
            System.out.println("Adding redirect uri: " + redirectUri);
            registeredClientBuilder.redirectUri(redirectUri);
        }

        for (String scope : clientConfigProperties.getScopes()) {
            if (OidcScopes.OPENID.equals(scope.toUpperCase())) {
                System.out.println("Adding scope openid");
                registeredClientBuilder.scope(OidcScopes.OPENID);
            } else {
                System.out.println("Adding scope: " + scope);
                registeredClientBuilder.scope(scope);
            }
        }

        return registeredClientBuilder.build();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public ProviderSettings providerSettings() {
        String issuer = authorizationServerProperties.getIssuer();
        System.out.println("**************************************");
        System.out.println("Found issuer uri: " + issuer);
        System.out.println("**************************************");
        return ProviderSettings.builder()
                .issuer(authorizationServerProperties.getIssuer())
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

}
