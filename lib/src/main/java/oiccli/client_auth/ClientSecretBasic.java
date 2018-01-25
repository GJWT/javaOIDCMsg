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

    public Map<String, Map<String, String>> construct(Map<String, String> cis, ClientInfo cliInfo, Map<String, Map<String, String>> httpArgs,
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
                password = cis.get("clientSecret");
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
        Map<String, String> hMap = httpArgs.get("headers");
        hMap.put("Authorization", "Basic " + authz);
        httpArgs.put("headers", hMap);

        cis.remove("clientSecret");

        if (cis.get("grantType").equals("authorizationCode")) {
            if (!cis.containsKey("clientId")) {
                cis.put("clientId", cliInfo.getClientId());
            }
        } else {
            boolean req;
            /*
            try:
                req = cis.c_param["client_id"][VREQUIRED]
            except KeyError:
                req = False
             */

            if (!req) {
                cis.remove("clientId");
            }
        }

        return httpArgs;
    }
}
