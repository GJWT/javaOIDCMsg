package com.auth0.jwt.oiccli;

import java.util.Map;

public class StateInfo {

    private String code;
    private String claim;
    private Token token;
    private String refreshToken;
    private String clientId;
    private String as;
    private long iat;

    public StateInfo(String clientId, String receiver, long now) {
        this.clientId = clientId;
        this.as = receiver;
        this.iat = now;
    }

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

    public void update(AuthorizationRequest request) {
        throw new UnsupportedOperationException();
    }
}
