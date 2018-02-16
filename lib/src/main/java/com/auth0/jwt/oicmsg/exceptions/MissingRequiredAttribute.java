package com.auth0.jwt.oicmsg.exceptions;

public class MissingRequiredAttribute extends Exception{
    public MissingRequiredAttribute(String message) {
        super(message);
    }
}
