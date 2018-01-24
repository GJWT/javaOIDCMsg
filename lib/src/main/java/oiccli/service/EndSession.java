package oiccli.service;

import com.auth0.jwt.creators.Message;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.MissingParameter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EndSession extends Service {
    private static EndSessionRequest endSessionRequest;
    private static Message message;
    private static ErrorResponse errorResponse;
    private static String endpointName = "endSessionEndpoint";
    private static boolean isSynchronous = true;
    private static String request = "endSession";

    public EndSession(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        //self.pre_construct = [self.oic_pre_construct]
    }

    public List<Map<String, String>> oicPreConstruct(ClientInfo clientInfo, Map<String, String> requestArgs, Map<String, String> args) throws MissingParameter {
        requestArgs = UserInfo.setIdToken(clientInfo, requestArgs, args);
        return Arrays.asList(requestArgs, new HashMap<String, String>());
    }

    /*
    def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, oiccli.Service):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    return service.factory(req_name, **kwargs)
     */
}
