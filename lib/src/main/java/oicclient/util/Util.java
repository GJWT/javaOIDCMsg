package oicclient.util;

import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import oicclient.exceptions.UnsupportedType;

public class Util {

    private static final String URL_ENCODED = "application/x-www-form-urlencoded";
    public static final String JSON_ENCODED = "application/json";

    public static Map<String, Object> getOrPost(String uri, String method, Message request, String contentType, List<String> accept, Map<String, Object> args) throws UnsupportedEncodingException, UnsupportedType, URISyntaxException {
        Map<String, Object> response = new HashMap<>();
        String urlEncoded;
        Field[] keys;
        Message requestClone;
        if (method.equals("GET") || method.equals("DELETE")) {
            keys = request.getClass().getDeclaredFields();
            if(keys != null) {
                requestClone = request.clone();
                URI url = new URI(uri);
                String query = url.getQuery();
                if(!Strings.isNullOrEmpty(query)) {
                    requestClone.update(splitQuery(query));
                }

                query = requestClone.toUrlEncoded();
                String urlResponse = uri + "?" + query;
                response.put("uri", urlResponse);
            } else {
                response.put("uri", uri);
            }
        } else if (method.equals("POST") || method.equals("PUT")) {
            response.put("uri", uri);
            if (contentType.equals(URL_ENCODED)) {
                response.put("body", request.toUrlEncoded());
            } else if (contentType.equals(JSON_ENCODED)) {
                response.put("body", request.toJSON());
            } else {
                throw new UnsupportedType("Unsupported content type " + contentType);
            }

            Map<String, Object> headers = new HashMap<>();
            headers.put("Content-Type", contentType);

            if (accept != null && !accept.isEmpty()) {
                headers = new HashMap<>();
                headers.put("Accept", accept);
            }
            if (args.containsKey("headers")) {
                if(args.get("headers") instanceof Message) {
                    ((Message) args.get("headers")).update(headers);
                } else {
                    throw new IllegalArgumentException("headers should be of type Message");
                }
            } else {
                args.put("headers", headers);
            }
            response.put("args", args);
        } else {
            throw new UnsupportedType("Unsupported HTTP method " + method);
        }

        return response;
    }

    public static Map<String, Object> getOrPost(String uri, String method, Message request, Map<String, Object> args) throws UnsupportedEncodingException, UnsupportedType, URISyntaxException {
        return getOrPost(uri, method, request, URL_ENCODED, null, args);
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
