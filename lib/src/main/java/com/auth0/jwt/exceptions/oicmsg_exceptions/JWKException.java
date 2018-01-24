package com.auth0.jwt.exceptions.oicmsg_exceptions;

public class JWKException extends Exception {

    public JWKException(String message) {
        super(message);
    }

    public JWKException() {
        super("JWKException");
    }
}