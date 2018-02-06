package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.MissingRequiredAttribute;
import com.google.common.base.Strings;
import java.util.HashMap;
import java.util.Map;

public class BearerHeader {

    public Map<String, Map<String, String>> construct(ResourceRequest resourceRequest, ClientInfo clientInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) throws MissingRequiredAttribute {
        String accessToken;
        if (resourceRequest != null) {
            if (!Strings.isNullOrEmpty(resourceRequest.getAccessToken())) {
                accessToken = resourceRequest.getAccessToken();
                resourceRequest.setAccessToken(null);
                resourceRequest.getCParam().setAccessToken(SINGLE_OPTIONAL_STRING);
            } else {
                accessToken = requestArgs.get("accessToken");

                if (Strings.isNullOrEmpty(accessToken)) {
                    accessToken = clientInfo.getStateDb().getTokenInfo(args).get("accessToken");
                }
            }
        } else {
            accessToken = args.get("accessToken");
            if (Strings.isNullOrEmpty(accessToken)) {
                throw new MissingRequiredAttribute("accessToken");
            }
        }

        String bearer = "Bearer " + accessToken;
        if (httpArgs == null) {
            Map<String, String> hMap = new HashMap<>();
            hMap.put("Authorization", bearer);
            httpArgs.put("headers", hMap);
        } else {
            Map<String, String> hMap = httpArgs.get("headers");
            if (hMap == null) {
                hMap = new HashMap<>();
            }
            hMap.put("Authorization", bearer);
            httpArgs.put("headers", hMap);
        }

        return httpArgs;
    }
}
