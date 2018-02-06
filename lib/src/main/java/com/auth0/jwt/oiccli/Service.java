package com.auth0.jwt.oiccli;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.HTTPError;
import com.auth0.jwt.oiccli.exceptions.MissingEndpoint;
import com.auth0.jwt.oiccli.exceptions.UnsupportedType;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.auth0.jwt.oiccli.exceptions.WrongContentType;
import com.auth0.jwt.oiccli.responses.ErrorResponse;
import com.auth0.jwt.oiccli.responses.Response;
import com.auth0.jwt.oiccli.util.FakeResponse;
import com.auth0.jwt.oiccli.util.Util;
import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.LoggerFactory;

public class Service {

    private final static org.slf4j.Logger logger = LoggerFactory.getLogger(Service.class);
    private static final List<Integer> successfulCodes =
            Arrays.asList(200, 201, 202, 203, 204, 205, 206);
    private static final List<String> specialArgs = Arrays.asList("authenticationEndpoint", "algs");
    public Message msgType;
    public Message responseCls;
    public ErrorResponse errorMessage;
    private String endpointName;
    private boolean isSynchronous = true;
    private String request;
    public String defaultAuthenticationMethod;
    public String httpMethod;
    public String bodyType;
    public String responseBodyType;
    private String endpoint;
    private String httpLib;
    private KeyJar keyJar;
    private String clientAuthenticationMethod;
    private List<String> events;
    private Map<String, String> defaultRequestArgs;
    protected List<Object> preConstruct;
    private List<String> postConstruct;
    protected List<String> postParseResponse;
    private Map<String,String> conf;

    public Service(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,String> conf) throws NoSuchFieldException, IllegalAccessException {
        this.httpLib = httpLib;
        this.keyJar = keyJar;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.events = new ArrayList<>();
        this.endpoint = "";
        this.defaultRequestArgs = new HashMap<>();

        if(conf != null) {
            this.conf = conf;
            List<String> params = Arrays.asList("msgType", "responseCls", "errorMessage", "defaultAuthenticationMethod",
                    "httpMethod", "bodyType", "responseBodyType");
            for(String param : params) {
                if(conf.containsKey(param)) {
                    this.getClass().getField(param).set(this, conf.get("param"));
                }
            }
        } else {
            this.conf = new HashMap<>();
        }

        this.preConstruct = new ArrayList<>();
        this.postConstruct = new ArrayList<>();
        this.postParseResponse = new ArrayList<>();
    }

    public void gatherRequestArgs() {
        throw new UnsupportedOperationException();
    }

    public void doPreConstruct() {
        throw new UnsupportedOperationException();
    }

    public void doPostConstruct() {
        throw new UnsupportedOperationException();
    }

    public void doPostParseResponse() {
        throw new UnsupportedOperationException();
    }

    public void construct() {
        throw new UnsupportedOperationException();
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
        for (String property : this.msgType.getCParam().keySet()) {
            if (!arArgs.containsKey(property)) {
                value = clientInfo.getClass().getField(property).get(this);
                if (value != null) {
                    arArgs.put(property, value);
                } else {
                    arArgs.put(property, this.defaultRequestArgs.get(property));
                }
            }
        }

        return arArgs;
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

    public Map<String, Map<String,String>> doRequestInit(ClientInfo clientInfo, String bodyType, String method, String authenticationMethod,
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

        Map<String,Map<String,String>> info = this.requestInfo(clientInfo, method, requestArgs, bodyType, authenticationMethod, false, args);

        return this.updateHttpArgs(httpArgs, info);
    }

    private Map<String,Map<String,String>> requestInfo(ClientInfo clientInfo, String method, Map<String, Object> requestArgs, String bodyType, String authenticationMethod, boolean b, Map<String, String> args) {
        throw new UnsupportedOperationException();
    }

    public String getUrlInfo(String info) throws URISyntaxException {
        String query = null;
        String fragment = null;
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

    public static ErrorResponse parseErrorMessage(String responseText, String bodyType) {
        String bodyTypeResult;
        if (bodyType.equals("txt")) {
            bodyTypeResult = "urlencoded";
        } else {
            bodyTypeResult = bodyType;
        }

        ErrorResponse errorResponse = new ErrorResponse().deserialize(responseText, bodyTypeResult);
        errorResponse.verify();

        return errorResponse;
    }

    public static String getValueType(FakeResponse response, String bodyType) throws WrongContentType, ValueError {
        if (!Strings.isNullOrEmpty(bodyType)) {
            return Util.verifyHeader(response, bodyType);
        } else {
            return "urlencoded";
        }
    }

    public static Response parseRequestResponse(FakeResponse response, ClientInfo clientInfo, String responseBodyType,
                                                     String state, Map<String, Object> args) throws ParseException, WrongContentType, ValueError, HTTPError {
        int statusCode = response.getStatusCode();
        if (successfulCodes.contains(statusCode)) {
            logger.debug("Response body type " + responseBodyType);
            String type = Util.getResponseBodyType(response);

            if(!type.equals(responseBodyType)) {
                logger.warn("Not the body type I expected: " + type + "!=" + responseBodyType);
            }
            List<String> types = Arrays.asList("json", "jwt", "urlencoded");
            String valueType;
            if(types.contains(type)) {
                valueType = type;
            } else {
                valueType = responseBodyType;
            }
            logger.debug("Successful response " + response.getText());
            return parseResponse(response.getText(), clientInfo, valueType, state, args);
        } else if (statusCode == 302 || statusCode == 303) {
            return response;
        } else if (statusCode == 500) {
            logger.error("(" + statusCode + ")" + response.getText());
            throw new ParseException("ERROR: Something went wrong " + response.getText(), 0);
        } else if (statusCode >= 400 && statusCode < 500) {
            logger.error("Error response (" + statusCode + "): " + response.getText());
            String valueType = getValueType(response, responseBodyType);
            return parseErrorMessage(response.getText(), valueType);
        } else {
            logger.error("Error response (" + statusCode + "):" + response.getText());
            throw new HTTPError("HTTP ERROR: " + response.getText() + "[" + statusCode + "]" + " on " + response.getUrl());
        }
    }

    public Response serviceRequest(String url, String method, String body, String responseBodyType, Map<String, String> httpArgs,
                                               ClientInfo clientInfo, Map<String, Object> args) throws ParseException, ValueError, WrongContentType {
        if (httpArgs == null) {
            httpArgs = new HashMap<>();
        }

        logger.debug("Doing request with: URL: " + url + ", method: " + method + ", data: " + body + ", https_args: " + httpArgs);
        FakeResponse response = this.httpLib(url, method, body, httpArgs);

        if (!args.containsKey("keyjar")) {
            args.put("keyjar", this.keyJar);
        }
        if (responseBodyType == null) {
            responseBodyType = this.responseBodyType;
        }

        return parseRequestResponse(response, clientInfo, responseBodyType, "", args);
    }

    public String getConfigurationAttribute(String attribute, String defaultValue) {
        if(this.conf.containsKey(attribute)) {
            return this.conf.get(attribute);
        } else {
            return defaultValue;
        }
    }

    public String getConfigurationAttribute(String attribute) {
        return getConfigurationAttribute(attribute, null);
    }

    public void buildServices() {
        throw new UnsupportedOperationException();
    }

    public Response serviceRequest(String url, Map<String, Object> args) throws ParseException, ValueError, WrongContentType {
        return serviceRequest(url, "GET", null, "", null, null, args);
    }

    public Response serviceRequest(String url, String method, ClientInfo clientInfo, Map<String, Object> args) throws ParseException, ValueError, WrongContentType {
        return serviceRequest(url, "GET", null, "", null, null, args);
    }

    public Response serviceRequest(String url, String method, ClientInfo clientInfo) throws ParseException, ValueError, WrongContentType {
        return serviceRequest(url, "GET", null, "", null, null, null);
    }

    private static FakeResponse parseResponse(Object text, ClientInfo clientInfo, String valueType, String state, Map<String, Object> args) {
        throw new UnsupportedOperationException();
    }

}
