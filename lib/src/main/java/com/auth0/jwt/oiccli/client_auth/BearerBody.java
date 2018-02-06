package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.oiccli.State;
import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.AuthenticationFailure;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.google.common.base.Strings;
import java.util.List;
import java.util.Map;

public class BearerBody {

    public Map<String, Map<String, String>> construct(ResourceRequest resourceRequest, ClientInfo clientInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, Object> args) throws AuthenticationFailure {

        if (Strings.isNullOrEmpty(resourceRequest.getAccessToken())) {
            AccessToken accessToken = args.get("accessToken");
            if (accessToken != null) {
                resourceRequest.setAccessToken(accessToken);
            } else {
                if (args.get("state") == null) {
                    State state = clientInfo.getStateDb();
                    if (state == null) {
                        throw new AuthenticationFailure("Missing state specification");
                    }

                    args.put("state", state);
                }

                resourceRequest.setAccessToken(clientInfo.getStateDb().getTokenInfo(args).get("accessToken"));
            }
        }

        return httpArgs;
    }

    public static JWT assertionJWT(String clientId, List<Key> keys, List<String> audience,
                                   String algorithm, int lifeTime) {
        long now = System.currentTimeMillis();

        AuthenticationToken at = new AuthenticationToken(clientId, clientId, audience, StringUtil.generateRandomString(32),
                now + lifeTime, now);
        return at.toJwt(keys, algorithm);
    }

    public static String bearerAuth(ResourceRequest resourceRequest, String authentication) throws ValueError {
        String accessToken = resourceRequest.getAccessToken();
        if(!Strings.isNullOrEmpty(accessToken)) {
            return accessToken;
        } else {
            if(!authentication.startsWith("Bearer ")) {
                throw new ValueError("Not a bearer token");
            }
            return authentication.substring(7);
        }
    }
}
