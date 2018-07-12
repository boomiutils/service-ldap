package com.boomi.flow.services.ldap;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.configuration.Configuration;

public class ApplicationConfiguration implements Configuration {

    @Configuration.Setting(name = "Host", contentType = ContentType.String)
    private String host;

    @Configuration.Setting(name = "Port", contentType = ContentType.String)
    private String port;

    @Configuration.Setting(name = "Base DN", contentType = ContentType.String)
    private String baseDn;

    @Configuration.Setting(name = "Principal", contentType = ContentType.String)
    private String principal;

    @Configuration.Setting(name = "Password", contentType = ContentType.Password)
    private String password;

    public String getHost() {
        return host;
    }

    public String getPort() {
        return port;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getPassword() {
        return password;
    }
}
