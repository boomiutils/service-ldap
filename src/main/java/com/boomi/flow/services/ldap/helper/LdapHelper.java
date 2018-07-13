package com.boomi.flow.services.ldap.helper;

// java imports
import com.sun.jndi.ldap.LdapCtxFactory;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Iterator;
import javax.naming.Context;
import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;

// flow imports
import com.boomi.flow.services.ldap.ApplicationConfiguration;
import com.manywho.sdk.api.security.AuthenticationCredentials;

public class LdapHelper {

    // app config
    private ApplicationConfiguration configuration;
    private AuthenticationCredentials credentials;

    public LdapHelper(ApplicationConfiguration config, AuthenticationCredentials creds){
        configuration = config;
        credentials = creds;
    }

    public LdapHelper(ApplicationConfiguration config){
        configuration = config;
    }

    public LdapUser authenticateUser() throws AuthenticationException {
        // object to return
        LdapUser user = new LdapUser();

        // bind by using the specified username/password
        Hashtable props = buildProps(credentials.getUsername(),credentials.getPassword(),configuration.getUidIdentifier(),configuration.getBaseDn());
        DirContext context;

        try {
            user = getUserFromLDAP(credentials.getUsername(),props, false, null, null);
        } catch (AuthenticationException a) {
            throw new AuthenticationException("Authentication failed: " + a);
        } catch (NamingException e) {
            throw new AuthenticationException("Failed to bind to LDAP / get account information: " + e);
        }
        return user;
    }

    public LdapUser authorizeUser(String userId) throws AuthenticationException {
        // object to return
        LdapUser user = new LdapUser();

        // bind by using the specified username/password
        Hashtable props = buildProps(configuration.getPrincipal(),configuration.getPassword(),configuration.getUidIdentifier(),configuration.getBaseDn());
        DirContext context;

        try {
            user = getUserFromLDAP(credentials.getUsername(),props, true, configuration.getGroupObjectClass(), userId);
        } catch (AuthenticationException a) {
            throw new AuthenticationException("Authentication failed: " + a);
        } catch (NamingException e) {
            throw new AuthenticationException("Failed to bind to LDAP / get account information: " + e);
        }
        return user;
    }

    public ArrayList<AuthorizationGroup> getLdapGroups() throws AuthenticationException {
        ArrayList<AuthorizationGroup> groups = new ArrayList<AuthorizationGroup>();
        // bind by using the specified username/password
        Hashtable props = buildProps(configuration.getPrincipal(),configuration.getPassword(),configuration.getUidIdentifier(),configuration.getBaseDn());
        DirContext context;

        try {
            context = LdapCtxFactory.getLdapCtxInstance("ldap://" + configuration.getHost(), props);
            // locate the groups
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            String filter = "(objectClass="+configuration.getGroupObjectClass()+")";
            NamingEnumeration<SearchResult> renum = context.search(configuration.getBaseDn(),filter, controls);
            if (!renum.hasMore()) {
                throw new AuthenticationException("Unable to locate any groups");
            }
            while (renum.hasMoreElements()){
                SearchResult result = renum.nextElement();
                if (result!=null){
                    AuthorizationGroup grp = new AuthorizationGroup();
                    Attributes attributes = result.getAttributes();
                    if (attributes != null){
                        if (attributes.get("cn")!=null){
                            grp.setId(attributes.get("cn").toString());
                            grp.setName(attributes.get("cn").toString());
                        }
                        if (attributes.get("description")!=null){
                            grp.setDescription(attributes.get("description").toString());
                        }
                    }
                    groups.add(grp);
                }
            }
        } catch (AuthenticationException a) {
            throw new AuthenticationException("Authentication failed: " + a);
        } catch (NamingException e) {
            throw new AuthenticationException("Failed to bind to LDAP / get account information: " + e);
        }
        return groups;
    }

    public ArrayList<AuthorizationUser> getLdapUsers() throws AuthenticationException {
        ArrayList<AuthorizationUser> users = new ArrayList<AuthorizationUser>();

        // bind by using the specified username/password
        Hashtable props = buildProps(configuration.getPrincipal(),configuration.getPassword(),configuration.getUidIdentifier(),configuration.getBaseDn());
        DirContext context;

        try {
            context = LdapCtxFactory.getLdapCtxInstance("ldap://" + configuration.getHost(), props);
            // locate the groups
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            String filter = "(objectClass="+configuration.getUserObjectClass()+")";
            NamingEnumeration<SearchResult> renum = context.search(configuration.getBaseDn(),filter, controls);
            if (!renum.hasMore()) {
                throw new AuthenticationException("Unable to locate any Users");
            }
            while (renum.hasMoreElements()){
                SearchResult result = renum.nextElement();
                if (result!=null){
                    AuthorizationUser usr = new AuthorizationUser();
                    Attributes attributes = result.getAttributes();
                    if (attributes != null){
                        String fullName = "";
                        if (attributes.get("uid")!=null){
                            usr.setId(attributes.get("uid").toString());
                        }
                        if (attributes.get("givenName")!=null){
                            fullName = attributes.get("givenName").toString();
                        }
                        if (attributes.get("sn")!=null){
                            fullName = fullName +" "+attributes.get("sn").toString();
                        }
                    }
                    users.add(usr);
                }
            }
        } catch (AuthenticationException a) {
            throw new AuthenticationException("Authentication failed: " + a);
        } catch (NamingException e) {
            throw new AuthenticationException("Failed to bind to LDAP / get account information: " + e);
        }
        return users;
    }

    private Hashtable buildProps(String userName, String password, String uidIdentifier, String baseDn){
        Hashtable props = new Hashtable();
        String principalName = userName;
        props.put(Context.SECURITY_PRINCIPAL, uidIdentifier+"="+principalName+","+baseDn+"");
        props.put(Context.SECURITY_CREDENTIALS, password);
        return props;
    }

    private LdapUser getUserFromLDAP(String userName, Hashtable props, boolean fetchGroups, String grpClassName, String userId) throws AuthenticationException{
        LdapUser user = null;
        DirContext context;
        try {
            context = LdapCtxFactory.getLdapCtxInstance("ldap://" + configuration.getHost(), props);
            // locate this user's record
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            String filter = "(&("+configuration.getUidIdentifier()+"=" + userId + ")(objectClass="+configuration.getUserObjectClass()+"))";
            NamingEnumeration<SearchResult> renum = context.search(configuration.getBaseDn(),filter, controls);
            if (!renum.hasMore()) {
                throw new AuthenticationException("Unable to locate user in directory");
            }
            SearchResult result = renum.next();
            if (result!=null){
                Attributes attributes = result.getAttributes();
                if (attributes != null){
                    if (attributes.get(configuration.getUidIdentifier()) != null){
                        user.setUsername(attributes.get(configuration.getUidIdentifier()).toString());
                    }
                    if (attributes.get("givenName")!=null){
                        user.setFirstName(attributes.get("givenName").toString());
                    }
                    if (attributes.get("sn") != null){
                        user.setLastName(attributes.get("sn").toString());
                    }
                    if (attributes.get("mail") != null){
                        user.setEmail(attributes.get("mail").toString());
                    }
                    if (attributes.get("displayName") != null){
                        user.setDisplayName(attributes.get("displayName").toString());
                    }
                }
            }

            if (fetchGroups){
                ArrayList<String> groups = new ArrayList<String>();
                Attribute memberOf = result.getAttributes().get(grpClassName);
                if (memberOf != null) {// null if this user belongs to no group at all
                    for (int i = 0; i < memberOf.size(); i++) {
                        Attributes atts = context.getAttributes(memberOf.get(i).toString(), new String[] { "CN" });
                        Attribute att = atts.get("CN");
                        groups.add(att.get().toString());
                    }
                }
                user.setGroups(groups);
            }
            context.close();

        } catch (AuthenticationException a) {
            throw new AuthenticationException("Authentication failed: " + a);
        } catch (NamingException e) {
            throw new AuthenticationException("Failed to bind to LDAP / get account information: " + e);
        }
        return user;
    }

    public boolean isMember(String grp){
        return true;
    }
}
