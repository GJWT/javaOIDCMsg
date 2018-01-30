package oiccli.client_auth;

import com.auth0.jwt.jwts.JWT;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import oiccli.StringUtil;
import oiccli.client_info.ClientInfo;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientSecretBasic extends ClientAuthenticationMethod {

    private final static Logger logger = LoggerFactory.getLogger(ClientSecretBasic.class);

    public static JWT assertionJwt(String clientId, List<Key> keys, List<String> audience, String algorithm, int lifetime) {
        long now = System.currentTimeMillis();
        String jti = StringUtil.generateRandomString(32);

        AuthenticationToken token = new AuthenticationToken(clientId, clientId, audience, jti, now + lifetime, now);
        logger.debug("AuthnToken " + token.toString());
        return token.toJWT(keys, algorithm);
    }

    public Map<String, Map<String, String>> construct(AccessTokenRequest request, ClientInfo cliInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) {
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
