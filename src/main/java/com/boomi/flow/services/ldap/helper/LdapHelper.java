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

    public LdapUser authenticateUser() throws AuthenticationException {
        // object to return
        LdapUser user = new LdapUser();

        // bind by using the specified username/password
        Hashtable props = new Hashtable();
        String principalName = credentials.getUsername();
        props.put(Context.SECURITY_PRINCIPAL, configuration.getUidIdentifier()+"="+principalName+","+configuration.getBaseDn()+"");
        props.put(Context.SECURITY_CREDENTIALS, credentials.getPassword());
        DirContext context;

        try {
            context = LdapCtxFactory.getLdapCtxInstance("ldap://" + configuration.getHost(), props);
            // locate this user's record
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            String filter = "(&("+configuration.getUidIdentifier()+"=" + principalName + ")(objectClass="+configuration.getUserObjectClass()+"))";
            NamingEnumeration<SearchResult> renum = context.search(configuration.getBaseDn(),filter, controls);
            if (!renum.hasMore()) {
                throw new AuthenticationException("Unable to locate user in directory");
            }
            SearchResult result = renum.next();
            if (result!=null){
                Attributes attributes = result.getAttributes();
                if (attributes != null){
                    if (attributes.get("userPrincipalName") != null){
                        user.setUsername(attributes.get("userPrincipalName").toString());
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
                        user.setDisplayName(attributes.get("diplayName").toString());
                    }
                }
            }

            /*
            ArrayList<String> groups = new ArrayList<String>();
            Attribute memberOf = result.getAttributes().get("memberOf");
            if (memberOf != null) {// null if this user belongs to no group at all
                for (int i = 0; i < memberOf.size(); i++) {
                    Attributes atts = context.getAttributes(memberOf.get(i).toString(), new String[] { "CN" });
                    Attribute att = atts.get("CN");
                    groups.add(att.get().toString());
                }
            }
            user.setGroups(groups);
            */
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
