package com.auth0.jwt.oicmsg.oic;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class AuthorizationErrorResponse extends com.auth0.jwt.oicmsg.oauth2.AuthorizationErrorResponse{

    public AuthorizationErrorResponse() {
        Map<String,List> cAllowedValues = getcAllowedValues();
        List list = cAllowedValues.get("error");
        list.addAll(Arrays.asList("interactionRequired",
                "loginRequired",
                "sessionSelectionRequired",
                "consentRequired",
                "invalidRequestUri",
                "invalidRequestObject",
                "registrationNotSupported",
                "requestNotSupported",
                "requestUriNotSupported"));
        cAllowedValues.put("error", list);
        updatecAllowedValues(cAllowedValues);
    }
}
