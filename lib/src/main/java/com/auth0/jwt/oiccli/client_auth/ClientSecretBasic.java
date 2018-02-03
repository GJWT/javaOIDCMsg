package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.oiccli.AccessTokenRequest;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.AuthenticationFailure;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class ClientSecretBasic {

    public Map<String, Map<String, String>> construct(AccessTokenRequest request, ClientInfo cliInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) throws AuthenticationFailure {
        if (httpArgs == null) {
            httpArgs = new HashMap<>();
        }

        if (!httpArgs.containsKey("headers")) {
            httpArgs.put("headers", new HashMap<String, String>());
        }

        String password = args.get("password");
        if (password == null) {
            password = httpArgs.get("password").get("password");
            if (password == null) {
                password = request.getClientSecret();
                if (password == null) {
                    password = cliInfo.getClientSecret();
                }
            }
        }

        String user = args.get("user");
        if (user == null) {
            user = cliInfo.getClientId();
        }

        String credentials = user + ":" + password;
        String authz = new String(Base64.encodeBase64(credentials.getBytes()));
        Map<String, String> hMap = new HashMap<>();
        hMap.put("Authorization", "Basic " + authz);
        httpArgs.put("headers", hMap);

        request.setClientSecret(null);

        if (request.get("grantType").equals("authorizationCode")) {
            if (request.getClientId() != null) {
                request.setClientId(cliInfo.getClientId());
            }
        } else {
            boolean req = request.getCParam("clientId").get(VREQUIRED);

            if (!req) {
                request.remove("clientId");
            }
        }

        return httpArgs;
    }
}
