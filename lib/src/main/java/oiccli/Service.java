package oiccli;

import com.auth0.jwt.creators.Message;
import com.google.common.base.Strings;
import javax.xml.ws.http.HTTPException;
import oiccli.HTTP.Response;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.MissingEndpoint;
import oiccli.exceptions.OicCliError;
import oiccli.exceptions.UnsupportedType;
import oiccli.exceptions.ValueError;
import oiccli.exceptions.WrongContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Service {

    private final static Logger logger = LoggerFactory.getLogger(Service.class);
    private static final List<Integer> successfulCodes =
            Arrays.asList(200, 201, 202, 203, 204, 205, 206);
    private static final List<String> specialArgs = Arrays.asList("authenticationEndpoint", "algs");
    private static final Map<String, Object> attributes = new HashMap<String, Object>() {{
        put("version", null);
        put("name", "");
        put("value", null);
        put("port", null);
        put("isPortSpecified", false);
        put("domain", "");
        put("isDomainSpecified", false);
        put("domainInitialDot", false);
        put("path", "");
        put("isPathSpecified", false);
        put("isSecure", false);
        put("expires", null);
        put("shouldDiscard", true);
        put("comment", null);
        put("commentUrl", null);
        put("rest", "");
        put("rfc2109", true);
    }};

    private Message msgType;
    private Message responseCls;
    private ErrorResponse errorResponse;
    private String endpointName;
    private boolean isSynchronous = true;
    private String request;
    private String defaultAuthenticationMethod;
    private String httpMethod;
    private String bodyType;
    private String responseBodyType;
    private String endpoint;
    private String httpLib;
    private KeyJar keyJar;
    private String clientAuthenticationMethod;
    private List<String> events;
    private Map<String, String> defaultRequestArgs;
    private List<Object> preConstruct;
    private List<String> postConstruct;
    private List<String> postParseResponse;


    public Service(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String, String> args) {
        this.httpLib = httpLib;
        this.keyJar = keyJar;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.events = new ArrayList<>();
        this.endpoint = "";
        this.defaultRequestArgs = new HashMap<>();
        this.preConstruct = new ArrayList<>();
        this.postConstruct = new ArrayList<>();
        this.postParseResponse = new ArrayList<>();
        this.httpMethod = "GET";
        this.bodyType = "urlencoded";
        this.responseBodyType = "json";
        this.defaultAuthenticationMethod = "";
        this.request = "";
        this.endpoint = "";
        this.endpointName = "";
        this.setUp();
    }

    public void gatherRequestArgs(ClientInfo clientInfo, Map<String, Object> args) {

    }

    public static Map<String, Map<String, String>> updateHttpArgs(Map<String, String> httpArgs, Map<String, Map<String, String>> info) {
        Map<String, String> hArgs = info.get("hArgs");
        if (hArgs == null) {
            hArgs = new HashMap<>();
        }

        if (httpArgs == null) {
            httpArgs = hArgs;
        } else {
            httpArgs.update(info.get("hArgs"));
        }

        final String headers = info.get("kwargs").get("headers");
        Map<String, String> hMap = new HashMap<String, String>() {{
            put("headers", headers);
        }};
        httpArgs.update(hMap);

        info.put("httpArgs", httpArgs);
        return info;
    }

    public Map<String, Object> parseArgs(ClientInfo clientInfo, Map<String, Object> args) throws NoSuchFieldException, IllegalAccessException {
        Map<String, Object> arArgs = new HashMap<>(args);
        Object value;
        for (String property : this.msgType.cParam.keySet()) {
            if (!arArgs.containsKey(property)) {
                value = clientInfo.getClass().getField(property).get(property);
                if (value != null) {
                    arArgs.put(property, value);
                } else {
                    arArgs.put(property, this.defaultRequestArgs.get(property));
                }
            }
        }

        return arArgs;
    }

    public List<Map<String, Object>> doPreConstruct(ClientInfo clientInfo, Map<String, Object> requestArgs, Map<String, String> args) {
        Map<String, Object> postArgs = new HashMap<>();
        for (Object method : this.preConstruct) {
                /*request_args, _post_args = meth(cli_info, request_args, **kwargs)
                post_args.update(_post_args)*/
        }

        return Arrays.asList(requestArgs, postArgs);
    }

    public Message doPostConstruct(ClientInfo clientInfo, Map<String, Object> requestArgs, Map<String, Object> postArgs) {

    }

    public void doPostParseResponse(Message response, ClientInfo clientInfo, String state, Map<String, KeyJar> args) {
        /*
          for meth in self.post_parse_response:
            meth(resp, cli_info, state=state, **kwargs)
         */
    }

    public Message constructMessage(ClientInfo clientInfo, Map<String, Object> requestArgs, Map<String, String> args) throws NoSuchFieldException, IllegalAccessException {

        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        List<Map<String, Object>> returnedArgs = this.doPreConstruct(clientInfo, requestArgs, args);

        if (!this.msgType.c_param.containsKey("state")) {
            args.remove("state");
        }

        Map<String, Object> argsParam = this.gatherRequestArgs(clientInfo, requestArgs);
        this.msgType(argsParam);

        return this.doPostConstruct(clientInfo, requestArgs, returnedArgs.get(1));
    }

    public String getEndpoint(Map<String, String> args) throws MissingEndpoint {
        String uri = args.get("endpoint");

        if (uri != null) {
            args.remove("endpoint");
        } else {
            if (!Strings.isNullOrEmpty(endpoint)) {
                uri = this.endpoint;
            } else {
                throw new MissingEndpoint("No endpoint specified");
            }
        }

        return uri;
    }

    public Map<String, Object> uriAndBody(Message cis, String method, Map<String, String> args) throws UnsupportedEncodingException, UnsupportedType, MissingEndpoint {
        String uri = this.getEndpoint(args);
        Map<String, Object> response = Util.getOrPost(uri, method, cis, args);
        response.put("cis", cis);
        Map<String, Object> hMap = new HashMap<>();
        hMap.put("headers", response.get("headers"));
        response.put("hArgs", hMap);

        return response;
    }

    public Map<String, String> initAuthenticationMethod(Message cis, ClientInfo clientInfo, String authenticationMethod,
                                                        Map<String, Object> httpArgs, Map<String, String> args) {
        return initAuthenticationMethod(cis, clientInfo, authenticationMethod, httpArgs, null, args);
    }

    public Map<String, String> initAuthenticationMethod(Message cis, ClientInfo clientInfo, String authenticationMethod,
                                                        Map<String, Object> requestArgs, Map<String, String> httpArgs, Map<String, String> args) {
        if (httpArgs == null) {
            httpArgs = new HashMap<>();
        }

        if (!Strings.isNullOrEmpty(authenticationMethod)) {
            //return this.client_authn_method[authn_method]().construct(
            //      cis, cli_info, request_args, http_args, **kwargs);
        } else {
            return httpArgs;
        }
    }

    public Map<String, Object> requestInfo(ClientInfo clientInfo, String method, Map<String, Object> requestArgs,
                                           String bodyType, String authenticationMethod, boolean lax, Map<String, String> args) throws NoSuchFieldException, IllegalAccessException, MissingEndpoint, UnsupportedEncodingException, UnsupportedType {
        if (method == null) {
            method = this.httpMethod;
        }

        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        Map<String, String> hMap = new HashMap<>();
        for (String key : args.keySet()) {
            if (args.get(key) != null && !specialArgs.contains(key)) {
                hMap.put(key, args.get(key));
            }
        }

        Message cis = this.constructMessage(clientInfo, requestArgs, args);

        if (this.events != null) {
            this.events.store("Protocol request", cis);
        }

        cis.setLax(lax);
        Map<String, String> hArg = new HashMap<>();
        if (!Strings.isNullOrEmpty(authenticationMethod)) {
            hArg = this.initAuthenticationMethod(cis, clientInfo, authenticationMethod, requestArgs, args);
        }

        if (hArg != null) {
            if (args.containsKey("headers")) {
                args.get("headers").update(hArg.get("headers"));
            } else {
                args.put("headers", hArg.get("headers"));
            }
        }

        if (bodyType.equals("json")) {
            args.put("contentType", "application/json");
        }

        return this.uriAndBody(cis, method, args);
    }

    public Map<String, Object> updateHttpArgs(Map<String, String> httpArgs, Map<String, Object> info) {
        Map<String, String> hArgs = info.get("hArgs");
        if (hArgs == null) {
            hArgs = new HashMap<>();
        }

        if (httpArgs == null) {
            httpArgs = hArgs;
        } else {
            httpArgs.update(info.get("h_args"));
        }

        info.put("httpArgs", httpArgs);
        return info;
    }

    public Map<String, Object> doRequestInit(ClientInfo clientInfo, String bodyType, String method, String authenticationMethod,
                                             Map<String, Object> requestArgs, Map<String, String> httpArgs, Map<String, String> args) throws NoSuchFieldException, IllegalAccessException, MissingEndpoint, UnsupportedEncodingException, UnsupportedType {
        if (Strings.isNullOrEmpty(method)) {
            method = this.httpMethod;
        }
        if (Strings.isNullOrEmpty(authenticationMethod)) {
            authenticationMethod = this.defaultAuthenticationMethod;
        }
        if (Strings.isNullOrEmpty(bodyType)) {
            bodyType = this.bodyType;
        }

        Map<String, Object> info = this.requestInfo(clientInfo, method, requestArgs, bodyType, authenticationMethod, false, args);

        return this.updateHttpArgs(httpArgs, info);
    }

    public String getUrlInfo(String info) throws URISyntaxException {
        String query = null, fragment = null;
        if (info.contains("?") || info.contains("#")) {
            URI uri = new URI(info);
            query = uri.getQuery();
            fragment = uri.getFragment();
        }

        if (!Strings.isNullOrEmpty(query)) {
            return query;
        } else {
            return fragment;
        }
    }

    public Message parseResponse(String info, ClientInfo clientInfo, String sFormat, String state,
                                 Map<String, Object> args) throws URISyntaxException, OicCliError {
        logger.debug("Response format: " + sFormat);

        if (sFormat.equals("urlencoded")) {
            info = this.getUrlInfo(info);
        }

        if (this.events != null) {
            this.events.store("Response", info);
        }

        logger.debug("Response cls: " + this.responseCls.getClass());

        Message response = this.responseCls.deserialize(info, sFormat, args);

        String message = "Initial response parsing => \"{}\"";
        logger.debug(message.format(response.toDict()));

        if (this.events != null) {
            this.events.store("Protocol Response", response);
        }

        List<ErrorResponse> errorMsgs;
        if (response.containsKey("error") && !(response instanceof ErrorResponse)) {
            response = null;
            errorMsgs = Arrays.asList(this.errorResponse);


            for (ErrorResponse errorMsg : errorMsgs) {
                response = errorMsg.deserialize(info, sFormat);
                response.verify();
                break;
            }

            logger.debug("Error response: " + response);
        } else {
            args.put("clientId", clientInfo.getClientId());
            args.put("issuer", clientInfo.getIssuer());

            if (!args.containsKey("key") && !args.containsKey("keyJar")) {
                args.put("keyJar", keyJar);
            }

            logger.debug("Verify response with " + args);

            boolean isVerificationSuccessful = response.verify(args);
            if (!isVerificationSuccessful) {
                logger.error("Verification of the response failed");
                throw new OicCliError("Verification of the response failed");
            }

            if (response.getType().equals("AuthorizationResponse") && response.getScope() == null) {
                response.setScope(args.get("scope"));
            }
        }

        if (response == null) {
            this.doPostParseResponse(response, clientInfo, state, args);
        }

        return response;
    }

    public ErrorResponse parseErrorMessage(Response response, String bodyType) {
        String bodyTypeResult;
        if (bodyType.equals("txt")) {
            bodyTypeResult = "urlencoded";
        } else {
            bodyTypeResult = bodyType;
        }

        ErrorResponse errorResponse = this.errorResponse.deserialize(response.getText(), bodyTypeResult);
        errorResponse.verify();

        return errorResponse;
    }

    public String getValueType(FakeResponse response, String bodyType) throws WrongContentType, ValueError {
        if (!Strings.isNullOrEmpty(bodyType)) {
            return Util.verifyHeader(response, bodyType);
        } else {
            return "urlencoded";
        }
    }

    public ErrorResponse parseRequestResponse(ErrorResponse response, ClientInfo clientInfo, String responseBodyType,
                                              String state, Map<String, Object> args) {
        int statusCode = response.getStatusCode();
        if (successfulCodes.contains(statusCode)) {
            logger.debug("Response body type " + responseBodyType);
            String valueType = this.getValueType(response, responseBodyType);
            logger.debug("Successful response " + response.getText());
            return this.parseResponse(response.getText(), clientInfo, valueType, state, args);
        } else if (statusCode == 302 || statusCode == 303) {
            return response;
        } else if (statusCode == 500) {
            logger.error("(" + statusCode + ")" + response.getText());
            throw new ParseException("ERROR: Something went wrong " + response.getText());
        } else if (statusCode >= 400 && statusCode < 500) {
            logger.error("Error response (" + statusCode + "): " + response.getText());
            String valueType = this.getValueType(response, responseBodyType);
            return this.parseErrorMessage(response, valueType);
        } else {
            logger.error("Error response (" + statusCode + "):" + response.getText());
            throw new HTTPException("HTTP ERROR: " + response.getText() + "[" + statusCode + "]" + " on " + response.getUrl());
        }
    }

    public static ErrorResponse serviceRequest(String url, String method, String body, String responseBodyType, Map<String, String> httpArgs,
                                               ClientInfo clientInfo, Map<String, Object> args) {
        if (httpArgs == null) {
            httpArgs = new HashMap<>();
        }

        logger.debug("Doing request with: URL: " + url + ", method: " + method + ", data: " + body + ", https_args: " + httpArgs);
        Response response = this.httpLib(url, method, body, httpArgs);

        if (!args.containsKey("keyjar")) {
            args.put("keyjar", this.keyJar);
        }
        if (responseBodyType == null) {
            responseBodyType = this.responseBodyType;
        }

        return parseRequestResponse(response, clientInfo, responseBodyType, "", args);
    }

    public static ErrorResponse serviceRequest(String url, Map<String, Object> args) {
        return serviceRequest(url, "GET", null, "", null, null, args);
    }

    public static ErrorResponse serviceRequest(String url, String method, ClientInfo clientInfo, Map<String, Object> args) {
        return serviceRequest(url, "GET", null, "", null, null, args);
    }

    public static ErrorResponse serviceRequest(String url, String method, ClientInfo clientInfo) {
        return serviceRequest(url, "GET", null, "", null, null, null);
    }
}
