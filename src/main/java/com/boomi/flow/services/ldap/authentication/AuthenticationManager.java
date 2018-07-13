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
import javax.naming.AuthenticationException;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

// flow impoorts
import com.boomi.flow.services.ldap.helper.LdapUser;
import com.boomi.flow.services.ldap.helper.LdapHelper;

public class AuthenticationManager {
    private final ConfigurationParser configurationParser;

    @Inject
    public AuthenticationManager(ConfigurationParser configurationParser) {
        this.configurationParser = configurationParser;
    }

    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials) {
        ApplicationConfiguration configuration = configurationParser.from(credentials);
        LdapUser user = null;
        LdapHelper helper = new LdapHelper(configuration, credentials);
        try {
            // Request an access token from Okta using the given authorization code
            if (helper!=null){
                user = helper.authenticateUser();
            }

        } catch (AuthenticationException e) {
            throw new RuntimeException("Unable to authenticate user against LDAP: " + e.getMessage(), e);
        }

        // Build up the profile result from the information LDAP gives us
        val result = new AuthenticatedWhoResult();
        result.setDirectoryId("ldap");
        result.setDirectoryName("LDAP");
        result.setEmail(user.getEmail());
        result.setFirstName(user.getFirstName());
        result.setIdentityProvider("LDAP");
        result.setLastName(user.getLastName());
        result.setStatus(AuthenticatedWhoResult.AuthenticationStatus.Authenticated);
        result.setTenantName("?");
        result.setToken("?");
        result.setUserId(user.getUsername());
        result.setUsername(user.getUsername());

        return result;
    }
}
