package com.auth0.jwt.oiccli.webfinger;

import com.auth0.jwt.oiccli.tuples.Tuple;
import com.auth0.jwt.oiccli.exceptions.WebFingerError;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import com.google.gson.Gson;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.LoggerFactory;

public class WebFinger {
    public String defaultRelt;
    public Object httpd;
    private JRD jrd;
    private List<Map<String, Object>> events;
    private static final String WF_URL = "https://%s/.well-known/webfinger";
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(WebFinger.class);
    private static final String OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";
    private static final Gson gson = new Gson();

    public WebFinger(String defaultRelt, Object httpd) {
        this.defaultRelt = defaultRelt;
        this.httpd = httpd;
        this.jrd = null;
        this.events = new ArrayList<>();
    }

    public String query(String resource, List<String> rel) throws URISyntaxException, WebFingerError {
        resource = new URINormalizer().normalize(resource);
        List<Tuple> queryParamsTuple = new ArrayList<>(Arrays.asList(new Tuple("resource", resource)));

        if (rel == null) {
            if (!Strings.isNullOrEmpty(this.defaultRelt)) {
                queryParamsTuple.add(new Tuple("rel", this.defaultRelt));
            }
        } else {
            for (String index : rel) {
                queryParamsTuple.add(new Tuple("rel", index));
            }
        }

        String host;
        if (resource.startsWith("http")) {
            URI uri = new URI(resource);
            host = uri.getHost();
            int port = uri.getPort();
            if (port != -1) {
                host += ":" + port;
            }
        } else if (resource.startsWith("acct:")) {
            String[] arr = resource.split("@");
            host = arr[arr.length - 1];
            arr = host.replace("/", "#").replace("?", "#").split("#");
            host = arr[0];
        } else if (resource.startsWith("device:")) {
            String[] arr = resource.split(":");
            host = arr[1];
        } else {
            throw new WebFingerError("Unknown schema");
        }

        String queryParams = "";
        for (int i = 0;
             i < queryParamsTuple.size();
             i++) {
            queryParams += queryParamsTuple.get(i).getA() + "=" + queryParamsTuple.get(i).getB();
            if (i != queryParamsTuple.size() - 1) {
                queryParams += "&";
            }
        }

        return String.format(WF_URL, host) + "?" + URLEncoder.encode(queryParams);
    }

    public Map<String, Object> httpArgs(JRD jrd) throws JsonProcessingException {
        if (jrd == null) {
            if (this.jrd != null) {
                jrd = this.jrd;
            } else {
                return null;
            }
        }

        Map<String, String> hMap = new HashMap<String, String>() {{
            put("Access-Control-Allow-Origin", "*");
            put("Content-Type", "application/json; charset=UTF-8");
        }};

        Map<String, Object> headersAndBody = new HashMap<>();
        headersAndBody.put("headers", hMap);
        headersAndBody.put("body", jrd.toJSON());

        return headersAndBody;
    }

    public static Object linkDeser(Object val, String sFormat) {
        if (val instanceof Map) {
            return val;
        } else if (sFormat.equals("dict") || sFormat.equals("json")) {
            if (!(val instanceof String)) {
                val = gson.toJson(val);
                sFormat = "json";
            }
        }

        return link().deserialize(val, sFormat);
    }

    /*public static Object messageSer(Object inst, String sFormat, int lev) throws MessageException, OicMsgError {
        Object res;
        if (sFormat.equals("urlencoded") || sFormat.equals("json")) {
            if (inst instanceof Map) {
                if (sFormat.equals("json")) {
                    res = gson.toJson(inst);
                } else {
                    res = Base64.encodeBase64URLSafe()
                }
            }
            //elif isinstance(inst, LINK):
            //res = inst.serialize(sformat, lev)
            else {
                res = inst;
            }
        } else if (sFormat.equals("dict")) {
            if (inst instanceof Map) {
                res = inst.serialize(sFormat, lev);
            } else if (inst instanceof String) {
                res = inst;
            } else {
                throw new MessageException("Wrong type: " + inst.getClass());
            }
        } else {
            throw new OicMsgError("Unknown sFormat" + inst);
        }

        return res;
    }*/
}
