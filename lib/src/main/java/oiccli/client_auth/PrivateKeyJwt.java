package oiccli.client_auth;

import oiccli.StringUtil;
import oiccli.exceptions.AuthenticationFailure;

import java.util.Map;

public class PrivateKeyJwt extends JWSAuthenticationMethod {

    public static String chooseAlgorithm(String entity, Map<String, String> args) throws AuthenticationFailure {
        return JWSAuthenticationMethod.chooseAlgorithm(entity, args);
    }

    public String chooseAlgorithm(Map<String, String> args) throws AuthenticationFailure {
        return chooseAlgorithm("private_key_jwt", args);
    }

    public Key getSigningKey(String algorithm, CliInfo cliInfo) {
        return cliInfo.keyjar.getSigningKey(StringUtil.alg2keytype(algorithm), "", algorithm);
    }
}
