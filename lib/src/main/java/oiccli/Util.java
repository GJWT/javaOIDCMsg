package oiccli;

import com.auth0.jwt.creators.Message;
import oiccli.exceptions.UnsupportedType;
import oiccli.exceptions.ValueError;
import oiccli.exceptions.WrongContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Util {

    private static final String URL_ENCODED = "application/x-www-form-urlencoded";
    private static final String JSON_ENCODED = "application/json";
    private static final String JWT_ENCODED = "application/jwt";
    private static final String JWT = "jwt";
    private static final String JSON = "json";
    private static final String URLENCODED = "urlencoded";
    private static final String DEFAULT_POST_CONTENT_TYPE = URL_ENCODED;
    Map<String, String> pairs = new HashMap<String, String>() {{
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

    public static Map<String, Object> getOrPost(String uri, String method, Message cis, Map<String, String> args) throws UnsupportedEncodingException, UnsupportedType {
        return getOrPost(uri, method, cis, "application/x-www-form-urlencoded", null, args);
    }

    public static Map<String, Object> getOrPost(String uri, String method, Message request, String contentType, String accept, Map<String, String> args) throws UnsupportedEncodingException, UnsupportedType {
        Map<String, Object> response = new HashMap<>();
        String urlEncoded;
        if (method.equals("GET") || method.equals("DELETE")) {
            urlEncoded = request.toUrlEncoded(request.toString());
            if (urlEncoded.contains("?")) {
                response.put("uri", uri + '&' + urlEncoded);
            } else {
                response.put("uri", uri + '?' + urlEncoded);
            }
        } else if (method.equals("POST") || method.equals("PUT")) {
            response.put("uri", uri);
            if (contentType.equals("application/x-www-form-urlencoded")) {
                response.put("body", request.toUrlEncoded(request.toString()));
            } else if (contentType.equals(JSON_ENCODED)) {
                response.put("body", request.toJSON(request.toHashMap()));
            } else {
                throw new UnsupportedType("Unsupported content type " + contentType);
            }

            Map<String, Object> headers = new HashMap<>();
            headers.put("Content-Type", contentType);

            if (accept != null) {
                headers = new HashMap<>();
                headers.put("Accept", accept);
            }
            if (args.containsKey("headers")) {
                //kwargs["headers"].update(header_ext)
            } else {
                args.put("headers", headers);
            }
        } else {
            throw new UnsupportedType("Unsupported HTTP method " + method);
        }

        return response;
    }

    public static void setCookie(CookieJar cookieJar, Map<String, Morsel> cookieMap) {
        Map<String, Object> attributesCopy;
        String codedValue;
        Morsel morsel;
        String morselValue;
        for (String cookieName : cookieMap.keySet()) {
            attributesCopy = new HashMap<>(attributes);
            attributesCopy.put("name", cookieName);
            morsel = cookieMap.get(cookieName);
            codedValue = morsel.getCodedValue();

            if (codedValue.startsWith("\"") && codedValue.endsWith("\"")) {
                attributesCopy.put("value", codedValue.substring(1, codedValue.length() - 1));
            } else {
                attributesCopy.put("value", codedValue);
            }

            attributesCopy.put("version", 0);
            String failedAttribute = null;
            try {
                for (String attribute : morsel.keySet()) {
                    failedAttribute = attribute;
                    if (attributes.containsKey(attribute)) {
                        morselValue = morsel.get(attribute);
                        if (StringUtil.isNotNullAndNotEmpty(morselValue)) {
                            if (attribute.equals("expires")) {
                                attributesCopy.put(attribute, dateToTime(morselValue));
                            } else {
                                attributesCopy.put(attribute, morselValue);
                            }
                        } else if (attribute.equals("maxAge")) {
                            if (StringUtil.isNotNullAndNotEmpty(morselValue)) {
                                attributesCopy.put("expires", dateToTime(morselValue));
                            }
                        }
                    }
                }
            } catch (ParseException e) {
                logger.info("Time format error on " + failedAttribute + " parameter in received cookie");
                continue;
            }

            for (String attribute : pairs.keySet()) {
                if (attributesCopy.get(attribute) != null) {
                    attributesCopy.put(pairs.get(attribute), true);
                }
            }

            if (attributesCopy.get("domain") instanceof String && StringUtil.isNotNullAndNotEmpty((String) attributesCopy.get("domain")) && ((String) attributesCopy.get("domain")).startsWith(".")) {
                attributesCopy.put("domainInitialDot", true);
            }

            if (morsel.getMaxAge() == 0) {
                cookieJar.clear(attributesCopy.getDomain(), attributesCopy.getPath(), attributesCopy.getName());
            } else {
                if (attributesCopy.containsKey("version")) {
                    attributesCopy.put("version", ((String) attributesCopy.get("version")).split(",")[0]);
                }

                Cookie newCookie = new Cookie();
                cookieJar.setCookie(newCookie);
            }
        }
    }

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

    public String verifyHeader(FakeResponse response, String bodyType) throws WrongContentType, ValueError {
        logger.debug("Response headers: " + response.getHeaders().toString());
        logger.debug("Response txt: " + response.getText().toString());

        String contentType = response.getHeaders().getContentType();
        if (!StringUtil.isNotNullAndNotEmpty(contentType)) {
            if (!StringUtil.isNotNullAndNotEmpty(bodyType)) {
                return bodyType;
            } else {
                return "txt";
            }
        }

        logger.debug("Expected body type: " + bodyType);

        if (bodyType.equals("")) {
            if (matchTo(JSON_ENCODED, contentType)) {
                bodyType = JSON;
            } else if (matchTo(JWT_ENCODED, contentType)) {
                bodyType = JWT;
            } else if (matchTo(URL_ENCODED, contentType)) {
                bodyType = URLENCODED;
            } else {
                bodyType = "txt";
            }
        } else if (bodyType.equals(JSON)) {
            if (matchTo(JSON_ENCODED, contentType)) {
                bodyType = JSON;
            } else if (matchTo(JWT_ENCODED, contentType)) {
                bodyType = JWT;
            } else {
                throw new WrongContentType(contentType);
            }
        } else if (bodyType.equals(JWT)) {
            if (!matchTo(JWT_ENCODED, contentType)) {
                throw new WrongContentType(contentType);
            }
        } else if (bodyType.equals(URLENCODED)) {
            if (!matchTo(DEFAULT_POST_CONTENT_TYPE, contentType) &&
                    !matchTo("text/plain", contentType)) {
                throw new WrongContentType(contentType);
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
}
