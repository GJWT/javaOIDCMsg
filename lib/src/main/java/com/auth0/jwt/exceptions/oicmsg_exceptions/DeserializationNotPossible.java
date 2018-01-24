package com.auth0.jwt.exceptions.oicmsg_exceptions;

public class DeserializationNotPossible extends JWKException {
    public DeserializationNotPossible(String message) {
        super(message);
    }

    public DeserializationNotPossible() {
        super();
    }
}