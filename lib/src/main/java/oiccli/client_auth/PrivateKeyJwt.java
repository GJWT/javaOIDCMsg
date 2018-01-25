package oiccli.client_auth;

import java.security.Key;
import java.util.Map;
import oiccli.StringUtil;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.AuthenticationFailure;

public class PrivateKeyJwt extends JWSAuthenticationMethod {

    public static String chooseAlgorithm(String entity, Map<String, String> args) throws AuthenticationFailure {
        return JWSAuthenticationMethod.chooseAlgorithm(entity, args);
    }

    @Override
    public String chooseAlgorithm(Map<String, String> args) throws AuthenticationFailure {
        return chooseAlgorithm("private_key_jwt", args);
    }

    @Override
    public Key getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(StringUtil.alg2keytype(algorithm), "", algorithm);
    }
}
