package com.auth0.jwt.oiccli.exceptions;

public class ExpiredToken extends Exception {
    public ExpiredToken(String message) {
        super(message);
    }
}
