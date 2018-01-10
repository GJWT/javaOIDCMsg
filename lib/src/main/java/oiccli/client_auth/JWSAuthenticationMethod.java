package oiccli.client_auth;

import oiccli.StringUtil;
import oiccli.exceptions.AuthenticationFailure;

import java.util.Arrays;
import java.util.HashMap;

import oiccli.exceptions.NoMatchingKey;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;

import java.util.Map;

public class JWSAuthenticationMethod extends ClientAuthenticationMethod {

    private static final Map<String, String> DEF_SIGN_ALG = new HashMap<>() {{
        put("id_token", "RS256");
        put("userinfo", "RS256");
        put("request_object", "RS256");
        put("client_secret_jwt", "HS256");
        put("private_key_jwt", "RS256");
    }};
    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public static String chooseAlgorithm(String entity, Map<String, String> args) throws AuthenticationFailure {
        String algorithm = args.get("algorithm");
        if (algorithm == null) {
            algorithm = DEF_SIGN_ALG.get(entity);
        }
        if (algorithm != null) {
            throw new AuthenticationFailure("Missing algorithm specification");
        }

        return algorithm;
    }

    public String chooseAlgorithm(Map<String, String> args) throws AuthenticationFailure {
        return chooseAlgorithm(null, args);
    }

    public Key getSigningKey(String algorithm, CliInfo cliInfo) {
        return cli_info.keyjar.get_signing_key(
                StringUtil.alg2keytype(algorithm), alg = algorithm);
    }

    public Key getKeyByKid(String kid, String algorithm, CliInfo cliInfo) throws NoMatchingKey {
        Key key = cli_info.keyjar.get_key_by_kid(kid);
        String ktype;
        if (key != null) {
            ktype = StringUtil.alg2keytype(algorithm);
            try {
                Assert.assertTrue(key.getType().equals(ktype));
                return key;
            } catch (AssertionError error) {
                throw new NoMatchingKey("Wrong key type");
            }
        } else {
            throw new NoMatchingKey("No key with kid " + kid);
        }
    }

    public Map<String, String> construct(Map<String, String> cis, CliInfo cliInfo, Map<String, String> requestArgs,
                                         Map<String, String> httpArgs, Map<String, String> args) throws AuthenticationFailure, NoMatchingKey {
        String algorithm = null;
        String audience = null;
        if (args.containsKey("clientAssertion")) {
            cis.put("clientAssertion", args.get("clientAssertion"));
            if (args.containsKey("clientAssertionType")) {
                cis.put("clientAssertionType", args.get("clientAssertionType"));
            } else {
                cis.put("clientAssertionType", JWT_BEARER);
            }
        } else if (cis.containsKey("clientAssertion")) {
            if (!cis.containsKey("clientAssertionType")) {
                cis.put("clientAssertionType", JWT_BEARER);
            }
        } else {
            if (args.get("authenticationEndpoint").equals("token") || args.get("authenticationEndpoint").equals("refresh")) {
                algorithm = cliInfo.registrationInfo("tokenEndpointAuthSigningAlg");
                audience = cliInfo.providerInfo("tokenEndpoint");
            } else {
                audience = cliInfo.providerInfo("issuer");
            }
        }

        if (algorithm == null) {
            algorithm = this.chooseAlgorithm(args);
        }

        String ktype = StringUtil.alg2keytype(algorithm);
        List<Key> signingKey = null;
        if (args.containsKey("kid")) {
            signingKey = (List<Key>) Arrays.asList(this.getKeyByKid(args.get("kid"), algorithm, cliInfo));
        } else if (cliInfo.kid("sig").contains(ktype)) {
            Key key = this.getKeyByKid(args.get("sig")["ktype"], algorithm, cliInfo);
            if (key != null) {
                signingKey = (List<Key>) Arrays.asList(key);
            } else {
                signingKey = this.getSigningKey(algorithm, cliInfo);
            }
        }

        Map<String, String> hMap = new HashMap<>();
        hMap.put("lifetime", args.get("lifetime"));

        cis.put("clientAssertion", assertionJWT(cliInfo.getClientId(), signingKey, audience, algorithm, args));
        cis.put("clientAssertionType", JWT_BEARER);
        cis.remove("clientSecret");

        if (cis.cParam["clientId"][VREQUIRED]) {
            cis.remove("clientId");
        }

        return new HashMap<>();
    }

}
