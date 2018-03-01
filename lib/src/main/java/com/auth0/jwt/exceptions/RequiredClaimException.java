package com.auth0.jwt.exceptions;

public class RequiredClaimException extends JWTVerificationException {
    public RequiredClaimException(String message) {
        super(message);
    }
}