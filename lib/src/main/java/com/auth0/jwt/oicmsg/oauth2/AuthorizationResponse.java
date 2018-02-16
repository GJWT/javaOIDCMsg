package com.auth0.jwt.oicmsg.oauth2;

import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import com.auth0.jwt.oicmsg.exceptions.ValueError;
import com.auth0.jwt.oicmsg.exceptions.VerificationError;
import java.util.Map;

public class AuthorizationResponse extends Message{

    public AuthorizationResponse(Map<String,Object> kwargs) {
        super(kwargs);
        Map<String,Tuple5> claims = getClaims();
        claims.put("code", SINGLE_REQUIRED_STRING);
        claims.put("state", SINGLE_OPTIONAL_STRING);
        claims.put("issuer", SINGLE_OPTIONAL_STRING);
        claims.put("clientId", SINGLE_OPTIONAL_STRING);

        setClaims(claims);
    }

    public AuthorizationResponse() {
    }

    public boolean verify(Map<String,Object> kwargs) throws Exception {
        super.verify(kwargs);
        Map<String,Object> claims = getDict();
        if(claims.containsKey("clientId")) {
            if (kwargs.containsKey("clientId")) {
                if(kwargs.get("clientId") instanceof String && !claims.get("clientId").equals((String) kwargs.get("clientId"))) {
                    throw new VerificationError("clientId mismatch");
                }
            } else {
                throw new ValueError("No clientId to verify against");
            }
        }

        if(claims.containsKey("issuer")) {
            if(kwargs.containsKey("issuer")) {
                if (claims.get("issuer") != null && !claims.get("issuer").equals(kwargs.get("issuer"))) {
                    throw new VerificationError("Issuer mismatch");
                }
            } else {
                throw new ValueError("No issuer set in the Client config");
            }
        }

        return true;
    }
}
