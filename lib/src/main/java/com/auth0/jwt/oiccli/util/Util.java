package com.auth0.jwt.oiccli.util;

import com.auth0.jwt.oiccli.AuthorizationRequest;
import com.auth0.jwt.oiccli.AuthorizationResponse;
import com.auth0.jwt.oiccli.exceptions.UnsupportedType;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.auth0.jwt.oiccli.exceptions.WrongContentType;
import com.auth0.jwt.oiccli.responses.Response;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Util {

    private static final String URL_ENCODED = "application/x-www-form-urlencoded";
    private static final String JSON_ENCODED = "application/json";
    private static final String JRD_JSON = "application/jrd+json";
    private static final String JWT_ENCODED = "application/jwt";
    private static final String PLAIN_TEXT = "text/plain";
    private static final String HTML_TEXT = "text/html";
    private static final String JWT = "jwt";
    private static final String JSON = "json";
    private static final String URLENCODED = "urlencoded";
    private static final String TEXT = "txt";
    private static final String DEFAULT_POST_CONTENT_TYPE = URL_ENCODED;
    private static final Map<String, String> pairs = new HashMap<String, String>() {{
        put("port", "portSpecified");
        put("domain", "domainSpecified");
        put("path", "pathSpecified");
    }};
    private static final Map<String, Object> attributes = new HashMap<String, Object>() {{
        put("version", null);
        put("name", "");
        put("value", null);
        put("port", null);
        put("portSpecified", false);
        put("domain", "");
        put("domainSpecified", false);
        put("domainInitialDot", false);
        put("path", "");
        put("pathSpecified", false);
        put("secure", false);
        put("expires", null);
        put("discard", true);
        put("comment", null);
        put("commentUrl", null);
        put("rest", "");
        put("rfc2109", true);
    }};
    private final static Logger logger = LoggerFactory.getLogger(Util.class);
    private final static Map<String, Integer> sortOrder = new HashMap<String, Integer>() {{
        put("RS", 0);
        put("ES", 1);
        put("HS", 2);
        put("PS", 3);
        put("no", 4);
    }};

    public static boolean matchTo(String value, List<String> valuesList) {
        for (String index : valuesList) {
            if (index.startsWith(value)) {
                return true;
            }
        }
        return false;
    }

    public static boolean matchTo(String value, String valueExpected) {
        return valueExpected.startsWith(value);
    }

    public String getResponseBodyType(Response response) throws ValueError {
        String contentType = response.getHeaders().get("contentType");
        if(Strings.isNullOrEmpty(contentType)) {
            throw new ValueError("Missing Content-type specification");
        }

        return getResponseBodyTypeHelperMethod(contentType);
    }

    public static String getResponseBodyTypeHelperMethod(String contentType) {
        String bodyType = null;
        if (matchTo(JSON_ENCODED, contentType) || matchTo(JRD_JSON, contentType)) {
            bodyType = JSON;
        } else if (matchTo(JWT_ENCODED, contentType)) {
            bodyType = JWT;
        } else if (matchTo(URL_ENCODED, contentType)) {
            bodyType = URLENCODED;
        }
        return bodyType;
    }

    public static String verifyHeader(FakeResponse response, String bodyType) throws WrongContentType, ValueError {
        logger.debug("Response headers: " + response.getHeaders().toString());
        logger.debug("Response txt: " + response.getText().toString());

        String contentType = response.getHeaders().getContentType();
        if (Strings.isNullOrEmpty(contentType)) {
            if (!Strings.isNullOrEmpty(bodyType)) {
                return bodyType;
            } else {
                return "txt";
            }
        }

        logger.debug("Expected body type: " + bodyType);

        if (bodyType.isEmpty()) {
            bodyType = getResponseBodyTypeHelperMethod(contentType);
            if(bodyType == null) {
                bodyType = TEXT;
            }
        } else if (bodyType.equals(JSON)) {
            if (matchTo(JWT_ENCODED, contentType)) {
                bodyType = JWT;
            } else if(!matchTo(JSON_ENCODED, contentType) || !matchTo(JRD_JSON, contentType)){
                throw new WrongContentType(contentType);
            }
        } else if (bodyType.equals(JWT)) {
            if (!matchTo(JWT_ENCODED, contentType)) {
                throw new WrongContentType(contentType);
            }
        } else if (bodyType.equals(URLENCODED)) {
            if (!matchTo(DEFAULT_POST_CONTENT_TYPE, contentType) &&
                    !matchTo(PLAIN_TEXT, contentType)) {
                throw new WrongContentType(contentType);
            }
        } else if (bodyType.equals(TEXT)) {
            if (!matchTo(PLAIN_TEXT, contentType) && !matchTo(HTML_TEXT, contentType)) {
                throw new WrongContentType("Content type: " + contentType);
            }
        } else {
            throw new ValueError("Unknown return format: " + bodyType);
        }

        logger.debug("Got body type: " + bodyType);
        return bodyType;
    }

    public Integer sortSignAlgorithm(String algorithm1, String algorithm2) {
        if (sortOrder.get(algorithm1.substring(0, 2)) < sortOrder.get(algorithm2.substring(0, 2))) {
            return -1;
        } else if (sortOrder.get(algorithm1.substring(0, 2)) > sortOrder.get(algorithm2.substring(0, 2))) {
            return 1;
        } else {
            return algorithm1.compareTo(algorithm2);
        }
    }

    public static long dateToTime(String date) throws ParseException {
        DateFormat inputFormat = new SimpleDateFormat("dd MMM yyy HH:mm:ss zz");
        Date d = inputFormat.parse(date);
        return d.getTime();
    }

    public static Map<String, Object> getOrPost(String uri, String method, AuthorizationRequest request, String contentType, boolean accept, Map<String, Object> args) throws UnsupportedEncodingException, UnsupportedType, JsonProcessingException, CloneNotSupportedException, URISyntaxException, NoSuchFieldException, IllegalAccessException {
        Map<String, Object> response = new HashMap<>();
        String urlEncoded;
        Field[] keys;
        AuthorizationRequest requestClone;
        AuthorizationResponse authorizationResponse = new AuthorizationResponse();
        if (method.equals("GET") || method.equals("DELETE")) {
            keys = request.getClass().getDeclaredFields();
            if(keys != null) {
                requestClone = (AuthorizationRequest) request.clone();
                URI url = new URI(uri);
                String query = url.getQuery();
                if(!Strings.isNullOrEmpty(query)) {
                    requestClone.update(splitQuery(query));
                }

                query = requestClone.toUrlEncoded();
                String urlResponse = uri + "?" + query;
                authorizationResponse.setUri(urlResponse);
            } else {
                authorizationResponse.setUri(uri);
            }
        } else if (method.equals("POST") || method.equals("PUT")) {
            authorizationResponse.setUri(uri);
            if (contentType.equals(URL_ENCODED)) {
                authorizationResponse.setBody(request.toUrlEncoded());
            } else if (contentType.equals(JSON_ENCODED)) {
                authorizationResponse.setBody(request.toJSON());
            } else {
                throw new UnsupportedType("Unsupported content type " + contentType);
            }

            Map<String, Object> headers = new HashMap<>();
            headers.put("Content-Type", contentType);

            if (accept) {
                headers = new HashMap<>();
                headers.put("Accept", accept);
            }
            if (args.containsKey("headers")) {
                //kwargs["headers"].update(header_ext)
            } else {
                args.put("headers", headers);
            }
            response.put("args", args);
        } else {
            throw new UnsupportedType("Unsupported HTTP method " + method);
        }

        return response;
    }

    private static Map<String,String> splitQuery(String query) throws UnsupportedEncodingException {
        Map<String, String> queryPairs = new LinkedHashMap<String, String>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }

        return queryPairs;
    }
}
