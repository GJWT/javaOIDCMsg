package oiccli.client_auth;

import com.auth0.jwt.jwts.JWT;
import oiccli.State;
import oiccli.StringUtil;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.AuthenticationFailure;

import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BearerBody {

    public Map<String, Map<String, String>> construct(Map<String, String> cis, ClientInfo clientInfo, Map<String, String> requestArgs, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, Object> args) throws AuthenticationFailure {
        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        if (!cis.containsKey("accessToken")) {
            String accessToken = requestArgs.get("accessToken");
            if (accessToken != null) {
                cis.put("accessToken", accessToken);
            } else {
                if (args.get("state") == null) {
                    State state = clientInfo.getState();
                    if (state == null) {
                        throw new AuthenticationFailure("Missing state specification");
                    }

                    args.put("state", state);
                }

                cis.put("accessToken", clientInfo.getStateDb().getTokenInfo(args).get("accessToken"));
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
}
