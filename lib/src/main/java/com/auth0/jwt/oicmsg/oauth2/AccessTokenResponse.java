package com.auth0.jwt.oicmsg.oauth2;

import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import java.util.Map;

public class AccessTokenResponse extends Message{
    public AccessTokenResponse() {
        Map<String,Tuple5> claims = getClaims();
        claims.put("accessToken", SINGLE_REQUIRED_STRING);
        claims.put("tokenType", SINGLE_REQUIRED_STRING);
        claims.put("expiresIn", SINGLE_OPTIONAL_INT);
        claims.put("refreshToken", SINGLE_OPTIONAL_STRING);
        claims.put("scope", OPTIONAL_LIST_OF_SP_SEP_STRINGS);
        claims.put("state", SINGLE_OPTIONAL_STRING);
        setClaims(claims);
    }
}
