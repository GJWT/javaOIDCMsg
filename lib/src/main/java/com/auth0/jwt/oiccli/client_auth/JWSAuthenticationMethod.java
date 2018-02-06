package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.AuthenticationFailure;
import com.auth0.jwt.oiccli.exceptions.NoMatchingKey;
import com.google.common.base.Strings;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;

public class JWSAuthenticationMethod extends ClientAuthenticationMethod {

    private static final Map<String, String> DEF_SIGN_ALG = new HashMap<String, String>() {{
        put("id_token", "RS256");
        put("userinfo", "RS256");
        put("request_object", "RS256");
        put("client_secret_jwt", "HS256");
        put("private_key_jwt", "RS256");
    }};
    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final int V_Required = 1;

    public static String chooseAlgorithm(String context, Map<String, String> args) throws AuthenticationFailure {
        String algorithm = args.get("algorithm");
        if (Strings.isNullOrEmpty(algorithm)) {
            algorithm = DEF_SIGN_ALG.get(context);
            if (Strings.isNullOrEmpty(algorithm)) {
                throw new AuthenticationFailure("Missing algorithm specification");
            }
        }

        return algorithm;
    }

    public String chooseAlgorithm(Map<String, String> args) throws AuthenticationFailure {
        return chooseAlgorithm(null, args);
    }

    public Key getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(
                StringUtil.alg2keytype(algorithm), algorithm);
    }

    public Key getKeyByKid(String kid, String algorithm, ClientInfo clientInfo) throws NoMatchingKey {
        Key key = clientInfo.getKeyJar().getKeyByKid(kid);
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

    public Map<String, String> construct(AccessTokenRequest request, ClientInfo clientInfo,
                                         Map<String, String> httpArgs, Map<String, String> args) throws AuthenticationFailure, NoMatchingKey {
        String algorithm = null;
        List<String> audience = null;
        if (args.containsKey("clientAssertion")) {
            request.setClientAssertion(args.get("clientAssertion"));
            if (args.containsKey("clientAssertionType")) {
                request.setClientAssertionType(args.get("clientAssertionType"));
            } else {
                request.setClientAssertionType(JWT_BEARER);
            }
        } else if (request.getClientAssertion() != null) {
            if (request.getClientAssertionType() == null) {
                request.setClientAssertionType(JWT_BEARER);
            }
        } else {
            if (args.get("authenticationEndpoint") != null && args.get("authenticationEndpoint").equals("token") || args.get("authenticationEndpoint") != null && args.get("authenticationEndpoint").equals("refresh")) {
                algorithm = clientInfo.getRegistrationResponse().get("tokenEndpointAuthSigningAlg").get(0);
                audience = clientInfo.getProviderInfo().get("tokenEndpoint");
            } else {
                audience = clientInfo.getProviderInfo().get("issuer");
            }
        }

        if (Strings.isNullOrEmpty(algorithm)) {
            algorithm = this.chooseAlgorithm(args);
        }

        String ktype = StringUtil.alg2keytype(algorithm);
        List<Key> signingKey = null;
        if (args.containsKey("kid")) {
            signingKey = Arrays.asList(this.getKeyByKid(args.get("kid"), algorithm, clientInfo));
        } else if (clientInfo.getKid().get("sig").containsKey(ktype)) {
            Key key = this.getKeyByKid(clientInfo.getKid().get("sig").get("ktype"), algorithm, clientInfo);
            if (key != null) {
                signingKey = Arrays.asList(key);
            } else {
                signingKey = Arrays.asList(this.getSigningKey(algorithm, clientInfo));
            }
        } else {
            signingKey = Arrays.asList(this.getSigningKey(algorithm, clientInfo));
        }

        Map<String, String> hMap = new HashMap<>();
        hMap.put("lifetime", args.get("lifetime"));

        request.setClientAssertion(BearerBody.assertionJWT(clientInfo.getClientId(), signingKey, audience, algorithm, 600));
        request.setClientAssertionType(JWT_BEARER);
        request.setClientSecret(null);

        if (request.getCParam.getClientId().get(V_Required) == null) {
            request.setClientId(null);
        }

        return new HashMap<>();
    }

}