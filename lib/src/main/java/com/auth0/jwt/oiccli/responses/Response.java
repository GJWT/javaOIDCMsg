package com.auth0.jwt.oiccli.responses;

import java.util.Map;

public class Response {

    private Map<String,String> headers;

    public String getText() {
        throw new UnsupportedOperationException();
    }

    public Map<String, String> getHeaders() {
        return headers;
    }
}
