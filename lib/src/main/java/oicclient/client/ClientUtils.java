package oicclient.client;

import java.util.HashMap;
import java.util.Map;

public class ClientUtils {

    private static final String RS256 = "RS256";
    private static final String HS256 = "HS256";
    private static final String ID_TOKEN = "idToken";
    private static final String USER_INFO = "userInfo";
    private static final String REQUEST_OBJECT = "requestObject";
    private static final String CLIENT_SECRET_JWT = "clientSecretJwt";
    private static final String PRIVATE_KEY_JWT = "privateKeyJwt";

    public static final Map<String,String> DEF_SIGN_ALG = new HashMap<String, String>() {{
        put(ID_TOKEN, RS256);
        put(USER_INFO, RS256);
        put(REQUEST_OBJECT, RS256);
        put(CLIENT_SECRET_JWT, HS256);
        put(PRIVATE_KEY_JWT, RS256);
    }};
}
