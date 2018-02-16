package com.auth0.jwt.oicmsg.oauth2;

import com.auth0.jwt.oicmsg.Tuple5;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class AuthorizationErrorResponse extends ErrorResponse{

    public AuthorizationErrorResponse() {
        Map<String, Tuple5> claims = getClaims();
        claims.put("state", SINGLE_OPTIONAL_STRING);
        updateClaims(claims);
        Map<String,List> cAllowedValueHashMap = getcAllowedValues();
        cAllowedValueHashMap.put("error", Arrays.asList("invalidRequest", "unauthorizedClient", "accessDenied",
                "unsupportedResponseType", "invalidScope", "serverError", "temporarilyUnavailable"));
        updatecAllowedValues(cAllowedValueHashMap);
    }
}
