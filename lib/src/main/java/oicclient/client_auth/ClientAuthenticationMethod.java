package oicclient.client_auth;

import com.auth0.jwt.creators.Message;
import java.util.Map;
import oicclient.exceptions.AuthenticationFailure;
import oicclient.exceptions.NoMatchingKey;

public abstract class ClientAuthenticationMethod {

    protected abstract void construct(Message request, ClientInfo clientInfo,
                             Map<String, String> httpArgs, Map<String, String> args) throws AuthenticationFailure, NoMatchingKey;
}
