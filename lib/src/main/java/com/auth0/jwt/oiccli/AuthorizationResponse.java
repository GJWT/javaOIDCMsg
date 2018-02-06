package com.auth0.jwt.oiccli;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.service.VerifiedIdToken;

public class AuthorizationResponse extends Message{

    private String uri;
    private String body;
    private VerifiedIdToken verifiedIdToken;

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public VerifiedIdToken getVerifiedIdToken() {
        return verifiedIdToken;
    }
}
