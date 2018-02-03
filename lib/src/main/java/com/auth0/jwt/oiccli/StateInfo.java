package com.auth0.jwt.oiccli;

import java.util.Map;

public class StateInfo {

    private String code;
    private String claim;
    private Token token;
    private String refreshToken;

    public void setCode(String code) {
        this.code = code;
    }

    public void setClaim(String claim) {
        this.claim = claim;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public void update(Map<String, Object> args) {
        throw new UnsupportedOperationException();
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
