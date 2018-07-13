package com.boomi.flow.services.ldap.authorization;

// misc imports
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Strings;
import com.google.inject.Inject;
import lombok.experimental.var;

// java imports
import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.Collectors;
import java.util.Iterator;
import javax.naming.AuthenticationException;

// flow impoorts
import com.boomi.flow.services.ldap.helper.LdapUser;
import com.boomi.flow.services.ldap.helper.LdapHelper;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.run.elements.config.Group;
import com.manywho.sdk.api.run.elements.config.User;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.manywho.sdk.services.types.TypeBuilder;
import com.manywho.sdk.services.types.system.$User;
import com.manywho.sdk.services.types.system.AuthorizationAttribute;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import com.manywho.sdk.services.utils.Streams;
import com.boomi.flow.services.ldap.ApplicationConfiguration;

public class AuthorizationManager {
    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;

    @Inject
    public AuthorizationManager(ConfigurationParser configurationParser, TypeBuilder typeBuilder) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
    }

    public ObjectDataResponse authorization(AuthenticatedWho authenticatedWho, ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);
        LdapHelper helper = new LdapHelper(configuration);
        LdapUser ldapUser = null;
        // deny everyone
        String status = "401";
        switch (request.getAuthorization().getGlobalAuthenticationType()) {
            case AllUsers:
                // If it's a public user (i.e. not logged in) then return a 401
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    status = "401";
                } else {
                    status = "200";
                }
                break;
            case Public:
                status = "200";
                break;
            case Specified:
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    break;
                }
                try {
                   ldapUser = helper.authorizeUser(authenticatedWho.getUserId());
                } catch (AuthenticationException e) {
                    break;
                }

                // We need to check if the authenticated user is one of the authorized users by ID
                if (request.getAuthorization().hasUsers() && ldapUser!=null) {
                    for (Iterator<User> iter = request.getAuthorization().getUsers().iterator(); iter.hasNext(); ) {
                        User u = iter.next();
                        if (ldapUser.getUsername().equals(u.getAuthenticationId())){
                            status = "200";
                            break;
                        }
                    }
                }

                // We need to check if the authenticated user is a member of one of the given groups, by group ID
                if (request.getAuthorization().hasGroups()) {
                    // If the user is a member of no groups, then they're automatically not authorized
                    if (ldapUser.getGroups() == null || ldapUser.getGroups().isEmpty()) {
                        break;
                    }
                    for (Iterator<Group> iter = request.getAuthorization().getGroups().iterator(); iter.hasNext(); ) {
                        Group g = iter.next();
                        if (ldapUser.getGroups().contains(g.getAuthenticationId())){
                            status = "200";
                            break;
                        }
                    }
                }
            default:
                status = "401";
                break;
        }
        var user = new $User();
        user.setDirectoryId("Ldap");
        user.setDirectoryName("Ldap");
        user.setAuthenticationType(AuthorizationType.UsernamePassword);
        //user.setLoginUrl(service.getAuthorizationUrl(additionalParameters));
        user.setStatus(status);
        user.setUserId("");

        return new ObjectDataResponse(typeBuilder.from(user));
    }

    public ObjectDataResponse groupAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("member", "Member"))
        );
    }

    public ObjectDataResponse groups(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);
        LdapHelper helper = new LdapHelper(configuration);

        try {
            ArrayList<AuthorizationGroup> groups = helper.getLdapGroups();
            return new ObjectDataResponse(
                    typeBuilder.from(groups)
            );
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        return null;
    }

    public ObjectDataResponse userAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("user", "User"))
        );
    }

    public ObjectDataResponse users(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);
        LdapHelper helper = new LdapHelper(configuration);

        try {
            ArrayList<AuthorizationUser> users = helper.getLdapUsers();
            return new ObjectDataResponse(
                    typeBuilder.from(users)
            );
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        return null;
    }
}
