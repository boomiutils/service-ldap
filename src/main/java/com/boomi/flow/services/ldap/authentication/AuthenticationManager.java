package com.boomi.flow.services.ldap.authentication;

import com.boomi.flow.services.ldap.ApplicationConfiguration;
import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import lombok.val;

import javax.inject.Inject;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class AuthenticationManager {
    private final ConfigurationParser configurationParser;

    @Inject
    public AuthenticationManager(ConfigurationParser configurationParser) {
        this.configurationParser = configurationParser;
    }

    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials) {
        ApplicationConfiguration configuration = configurationParser.from(credentials);

        // Build up the profile result from the information LDAP gives us
        val result = new AuthenticatedWhoResult();
        result.setDirectoryId("ldap");
        result.setDirectoryName("LDAP");
        result.setEmail("test@gmail.com");
        result.setFirstName("Test");
        result.setIdentityProvider("?");
        result.setLastName("User");
        result.setStatus(AuthenticatedWhoResult.AuthenticationStatus.Authenticated);
        result.setTenantName("?");
        result.setToken("?");
        result.setUserId("12345");
        result.setUsername("testusername@gmail.com");

        return result;
    }
}
