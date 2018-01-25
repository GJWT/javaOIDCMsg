package oiccli.service;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import oiccli.AuthorizationResponse;
import oiccli.StringUtil;
import oiccli.client_info.ClientInfo;

public class Authorization extends service.Authorization {

    private AuthorizationRequest authorizationRequest;
    private AuthorizationResponse authorizationResponse;
    private AuthorizationErrorResponse authorizationErrorResponse;
    private Map<String, List<String>> defaultRequestArgs;
    private List<>

    public Authorization(Object httpLib, Object keyJar, Map<String, Class> clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        this.defaultRequestArgs = new HashMap() {{
            put("scope", Arrays.asList("openId"));
        }};
        /*self.pre_construct = [self.oic_pre_construct]
        self.post_construct = [self.oic_post_construct]*/
    }

    public List<Map<String, ?>> oicPreConstruct(ClientInfo clientInfo, Map<String, Object> requestArgs, Map<String, String> args) {
        if (requestArgs != null) {
            String responseType = (String) requestArgs.get("responseType");
            if (responseType == null) {
                requestArgs.put("responseType", clientInfo.getBehavior().get("responseTypes").get(0));

            }

            if (responseType.contains("token") || responseType.contains("idToken")) {
                if (!requestArgs.containsKey("nonce")) {
                    requestArgs.put("nonce", StringUtil.generateRandomString(32));
                }
            }
        } else {
            requestArgs = new HashMap() {{
                put("nonce", StringUtil.generateRandomString(32));
            }};
        }

        Map<String, String> postArgs = new HashMap<>();
        for (String attribute : Arrays.asList("requestObjectSigningAlg", "algorithm", "sigKid")) {
            postArgs.put(attribute, args.get(attribute));
            args.remove(attribute);
        }

        if (args.containsKey("requestMethod")) {
            if (args.get("requestMethod").equals("reference")) {
                postArgs.put("requestParam", "requestUri");
            } else {
                postArgs.put("requestParam", "request");
            }
            args.remove("requestMethod");
        }

        List<String> responseMode = clientInfo.getBehavior().get("responseMode");
        if (responseMode.contains("formPost")) {
            requestArgs.put("responseMode", responseMode);
        }

        if (!requestArgs.containsKey("state")) {
            requestArgs.put("state", clientInfo.getStateDb().createState(clientInfo.getIssuer(), requestArgs));
        }

        return Arrays.asList(requestArgs, postArgs);
    }

    public Map<String, String> oicPostConstruct(ClientInfo clientInfo, Map<String, String> req, Map<String, String> args) {
        String requestParam = args.get("requestParam");
        args.remove("requestParam");

        String algorithm = null;
        for (String argument : Arrays.asList("requestObjectSigningAlg", "algorithm")) {
            algorithm = args.get(argument);
        }

        if (algorithm == null) {
            algorithm = clientInfo.getBehavior().get("requestObjectSigningAlg");
            if (algorithm == null) {
                algorithm = "RS256";
            }
        }

        args.put("requestObjectSigningAlg", algorithm);

        if (!args.containsKey("keys") && algorithm != null && !algorithm.equals("none")) {
            String kty = StringUtil.alg2keytype(algorithm);
            String kid = args.get("sigKid");
            if (kid == null) {
                kid = clientInfo.getKid().get("sig").get(kty);
            }
            args.put("keys", clientInfo.getKeyJar().getSigningKey(kty, kid));
        }

        /*
            _req = make_openid_request(req, **kwargs)

            # Should the request be encrypted
            _req = request_object_encryption(_req, cli_info, **kwargs)
         */

        if (requestParam.equals("request")) {
            req.put("request", _req);
        } else {
            //_webname = cli_info.registration_response['request_uris'][0]
            String fileName = clientInfo.filenameFromWebname(webName);
            //except KeyError:
            //filename, _webname = construct_request_uri(**kwargs)
            BufferedWriter writer = null;
            try {
                writer = new BufferedWriter(new FileWriter(fileName));
                writer.write(_req);
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            req.put("requestUri", _webname);
        }

        return req;
    }
}
