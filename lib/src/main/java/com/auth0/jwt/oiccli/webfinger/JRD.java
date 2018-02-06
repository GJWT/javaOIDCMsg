package com.auth0.jwt.oiccli.webfinger;

import java.util.List;
import java.util.Map;

public class JRD {

    private List<Map<String,String>> links;

    public String toJSON() {
        return "";
    }

    public List<Map<String,String>> getLinks() {
        return links;
    }
}
