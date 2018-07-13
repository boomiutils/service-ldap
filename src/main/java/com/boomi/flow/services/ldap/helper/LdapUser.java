package com.boomi.flow.services.ldap.helper;

// java imports
import java.util.ArrayList;

public class LdapUser {

    // user ldap attributes
    private String userName;
    private String firstName;
    private String lastName;
    private String email;
    private String displayName;
    //private ArrayList<String> groups = new ArrayList<String>();

    // getters
    public String getUsername(){return userName;}
    public String getFirstName(){return firstName;}
    public String getLastName(){return lastName;}
    public String getEmail(){return email;}
    public String getDisplayName(){return displayName;}
   // public ArrayList<String> getGroups(){return groups;}

    // setters
    public void setUsername(String s){userName = s;}
    public void setFirstName(String s){firstName = s;}
    public void setLastName(String s){lastName = s;}
    public void setEmail(String s){email = s;}
    public void setDisplayName(String s){displayName = s;}
    //public void setGroups(ArrayList<String> grps){groups = grps;}

}