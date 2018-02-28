package oicclient.client_auth;

import oicclient.clientinfo.ClientInfo;
import java.util.Map;

public class PrivateKeyJwt extends JWSAuthenticationMethod{

    protected String chooseAlgorithm(Map<String,String> args) {
        return chooseAlgorithm("privateKeyJwt", args);
    }

    protected List<Key> getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(alg2KeyType(algorithm), "", algorithm);
    }
}