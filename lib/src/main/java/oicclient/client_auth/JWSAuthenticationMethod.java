package oicclient.client_auth;

import com.auth0.jwt.creators.Message;
import com.google.common.base.Strings;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import oicclient.client.ClientUtils;
import oicclient.clientinfo.ClientInfo;
import oicclient.exceptions.AuthenticationFailure;
import oicclient.exceptions.NoMatchingKey;

public class JWSAuthenticationMethod extends ClientAuthenticationMethod {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    protected String chooseAlgorithm(String context, Map<String, String> args) throws AuthenticationFailure {
        String algorithm = args.get("algorithm");
        if (Strings.isNullOrEmpty(algorithm)) {
            algorithm = ClientUtils.DEF_SIGN_ALG.get(context);
            if (Strings.isNullOrEmpty(algorithm)) {
                throw new AuthenticationFailure("Missing algorithm specification");
            }
        }

        return algorithm;
    }

    protected List<Key> getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(alg2KeyType(algorithm), algorithm);
    }

    private Key getKeyByKid(String kid, String algorithm, ClientInfo clientInfo) throws NoMatchingKey {
        Key key = clientInfo.getKeyJar().getKeyByKid(kid);
        if (key != null) {
            String keyType = alg2KeyType(algorithm);
            if (!key.getKeyType().equals(keyType)) {
                throw new NoMatchingKey("Wrong key type");
            } else {
                return key;
            }
        } else {
            throw new NoMatchingKey("No key with kid: " + kid);
        }
    }

    protected void construct(Message request, ClientInfo clientInfo,
                             Map<String, String> httpArgs, Map<String, String> args) throws AuthenticationFailure, NoMatchingKey {
        String algorithm = null;
        List<String> audience = null;
        Map<String, String> cParams = request.getCParams();
        if (args.containsKey("clientAssertion")) {
            cParams.put("clientAssertion", args.get("clientAssertion"));
            if (args.containsKey("clientAssertionType")) {
                cParams.put("clientAssertionType", args.get("clientAssertionType"));
            } else {
                cParams.put("clientAssertionType", JWT_BEARER);
            }
        } else if (cParams.containsKey("clientAssertion")) {
            if (!cParams.containsKey("clientAssertionType")) {
                cParams.put("clientAssertionType", JWT_BEARER);
            }
        } else {
            if ((args.get("authenticationEndpoint") != null && args.get("authenticationEndpoint").equals("token")) || (args.get("authenticationEndpoint") != null && args.get("authenticationEndpoint").equals("refresh"))) {
                algorithm = clientInfo.getRegistrationResponse().get("tokenEndpointAuthSigningAlg").get(0);
                audience = clientInfo.getProviderInfo().get("tokenEndpoint");
            } else {
                audience = clientInfo.getProviderInfo().get("issuer");
            }
        }

        if (Strings.isNullOrEmpty(algorithm)) {
            //how is this going to call a subclass?
            algorithm = this.chooseAlgorithm(args);
        }

        String ktype = alg2keytype(algorithm);
        List<Key> signingKey = null;
        if (args.containsKey("kid")) {
            signingKey = Arrays.asList(this.getKeyByKid(args.get("kid"), algorithm, clientInfo));
        } else if (clientInfo.getKid().get("sig").containsKey(ktype)) {
            Key key = this.getKeyByKid(clientInfo.getKid().get("sig").get(ktype), algorithm, clientInfo);
            if (key != null) {
                signingKey = Arrays.asList(key);
            } else {
                signingKey = this.getSigningKey(algorithm, clientInfo);
            }
        } else {
            signingKey = this.getSigningKey(algorithm, clientInfo);
        }

        int lifetime = -1;
        if (!Strings.isNullOrEmpty(args.get("lifetime"))) {
            lifetime = Integer.parseInt(args.get("lifetime"));
        }
        if(lifetime != -1) {
            cParams.put("clientAssertion", assertionJWT(clientInfo.getClientId(), signingKey, audience, algorithm, lifetime));
        } else {
            cParams.put("clientAssertion", assertionJWT(clientInfo.getClientId(), signingKey, audience, algorithm, 600));
        }
        cParams.put("clientAssertionType", JWT_BEARER);

        cParams.remove("clientSecret");

        if (cParams.get("clientId") != null && !cParams.get("clientId").getB()) {
            cParams.remove("clientId");
        }

        request.setCParams(cParams);
    }
}
