package oiccli.client_auth;

import com.auth0.jwt.jwts.JWT;

import oiccli.StringUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClientSecretBasic extends ClientAuthenticationMethod {

    private final static Logger logger = LoggerFactory.getLogger(ClientAuth.class);

    public static JWT assertionJwt(String clientId, List<Key> keys, List<String> audience, String algorithm, int lifetime) {
        long now = System.currentTimeMillis();
        String jti = StringUtil.generateRandomString(32);

        AuthToken token = new AuthToken(clientId, clientId, audience, jti, now + lifetime, now);
        logger.debug("AuthnToken " + token.toString());
        return token.toJWT(keys, algorithm);
    }

    public Map<String, Map<String, String>> construct(Map<String, String> cis, CliInfo cliInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) {
        if (httpArgs == null) {
            httpArgs = new HashMap<>();
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

        if (!httpArgs.keySet().contains("headers")) {
            httpArgs.put("headers", null);
        }

        String credentials = user + ":" + password;
        String authz = Base64.encodeBase64(credentials.getBytes());
        Map<String, String> hMap = httpArgs.get("headers");
        hMap.put("Authorization", "Basic " + authz);


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
