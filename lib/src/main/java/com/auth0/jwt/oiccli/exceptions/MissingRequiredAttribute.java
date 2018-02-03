package com.auth0.jwt.oiccli.exceptions;

public class MissingRequiredAttribute extends Exception{
    public MissingRequiredAttribute(String message) {
        super(message);
    }
}
