package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.oiccli.AccessTokenRequest;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.AuthenticationFailure;
import com.google.common.base.Strings;
import java.util.Map;

public class ClientSecretPost extends ClientSecretBasic {

    public Map<String, Map<String, String>> construct(AccessTokenRequest request, ClientInfo clientInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) throws AuthenticationFailure {
        if (Strings.isNullOrEmpty(request.getClientSecret())) {
            Map<String, String> clientSecret = httpArgs.get("clientSecret");
            if (clientSecret != null) {
                request.setClientSecret(clientSecret.get("clientSecret"));
                httpArgs.remove("clientSecret");
            } else {
                if (!Strings.isNullOrEmpty(clientInfo.getClientSecret())) {
                    request.setClientSecret(clientInfo.getClientSecret());
                } else {
                    throw new AuthenticationFailure("Missing client secret");
                }
            }
        }

        request.setClientId(clientInfo.getClientId());

        return httpArgs;
    }
}