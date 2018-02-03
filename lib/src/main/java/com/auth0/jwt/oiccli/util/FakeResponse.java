package com.auth0.jwt.oiccli.util;

import com.auth0.jwt.oiccli.responses.Response;

public class FakeResponse extends Response {

    private Header headers;
    private String text;
    private int statusCode;
    private String url;

    public Header getHeaders() {
        return headers;
    }

    public String getText() {
        return text;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getUrl() {
        return url;
    }
}
