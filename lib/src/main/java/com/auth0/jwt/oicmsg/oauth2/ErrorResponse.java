package com.auth0.jwt.oicmsg.oauth2;

import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import java.util.HashMap;
import java.util.Map;

public class ErrorResponse extends Message{
    public ErrorResponse() {
        Map<String,Tuple5> claims = new HashMap<String,Tuple5>() {{
            put("error", SINGLE_REQUIRED_STRING);
            put("errorDescription", SINGLE_OPTIONAL_STRING);
            put("errorUri", SINGLE_OPTIONAL_STRING);
        }};
        setClaims(claims);
    }
}
