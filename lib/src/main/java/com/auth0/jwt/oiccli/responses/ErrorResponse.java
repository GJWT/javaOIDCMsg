package com.auth0.jwt.oiccli.responses;

public class ErrorResponse extends Response{

    private int statusCode;
    private String text;

    public void verify() {
        throw new UnsupportedOperationException();
    }

    public ErrorResponse deserialize(String text, String bodyTypeResult) {
        throw new UnsupportedOperationException();
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getText() {
        return text;
    }
}
