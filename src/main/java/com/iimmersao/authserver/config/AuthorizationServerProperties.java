package com.iimmersao.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@ConfigurationProperties(prefix = "spring.security.oauth2.authorizationserver")
public class AuthorizationServerProperties {

    private String issuer;
    private Map<String, Client> client;

    public String getIssuer() {
        return issuer;
    }

    @Override
    public String toString() {
        return "AuthorizationServerProperties{" +
                "issuer='" + issuer + '\'' +
                ", client=" + client +
                '}';
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Map<String, Client> getClient() {
        return client;
    }

    public void setClient(Map<String, Client> client) {
        this.client = client;
    }

    public static class Client {
        private Registration registration;

        @Override
        public String toString() {
            return "Client{" +
                    "registration=" + registration +
                    '}';
        }

        public Registration getRegistration() {
            return registration;
        }

        public void setRegistration(Registration registration) {
            this.registration = registration;
        }
    }

}
