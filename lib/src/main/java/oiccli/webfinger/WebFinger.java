package oiccli.webfinger;

import com.google.common.base.Strings;
import com.sun.deploy.net.HttpResponse;
import oiccli.HTTP.Response;
import oiccli.Tuple;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.WebFingerError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.*;

public class WebFinger {

    public String defaultRelt;
    public Object httpd;
    private JRD jrd;
    private List<Map<String,Object>> events;
    private static final String WF_URL = "https://%s/.well-known/webfinger";
    final private static Logger logger = LoggerFactory.getLogger(WebFinger.class);
    private static final String OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";

    public WebFinger(String defaultRelt, Object httpd) {
        this.defaultRelt = defaultRelt;
        this.httpd = httpd;
        this.jrd = null;
        this.events = new ArrayList<>();
    }

    public String query(String resource, List<String> rel) throws URISyntaxException, WebFingerError {
        resource = new URINormalizer().normalize(resource);
        List<Tuple> queryParamsTuple = new ArrayList<>();
        queryParamsTuple.add(new Tuple("resource", resource));

        if(rel == null) {
            if(this.defaultRelt != null) {
                queryParamsTuple.add(new Tuple("rel", this.defaultRelt));
            }
        } else {
            for(String index : rel) {
                queryParamsTuple.add(new Tuple("rel", index));
            }
        }

        String host;
        if(resource.startsWith("http")) {
            URI uri = new URI(resource);
            host = uri.getHost();
            int port = uri.getPort();
            if(port != -1) {
                host += ":" + port;
            }
        } else if(resource.startsWith("acct:")) {
            String[] arr = resource.split("@");
            host = arr[arr.length-1];
            arr = host.replace("/", "#").replace("?", "#").split("#");
            host = arr[0];
        } else if(resource.startsWith("device:")) {
            String[] arr = resource.split(":");
            host = arr[1];
        } else {
            throw new WebFingerError("Unknown schema");
        }
        
        String queryParams = "";
        for(int i = 0; i < queryParamsTuple.size(); i++) {
            queryParams += queryParamsTuple.get(i).getA() + "=" + queryParamsTuple.get(i).getB();
            if(i != queryParamsTuple.size()-1) {
                queryParams += "&";
            }
        }

        return String.format(WF_URL, host) + "?" + URLEncoder.encode(queryParams);
    }

    public static JRD load(Map<String,Object> item) {
        return new JRD(json.loads(item));
    }

    public Map<String,Map<String,String>>  httpArgs(JRD jrd) {
        if(jrd == null) {
            if(this.jrd != null) {
                jrd = this.jrd;
            } else {
                return null;
            }
        }

        Map<String,String> hMap = new HashMap<String, String>() {{
                put("Access-Control-Allow-Origin", "*");
                put("Content-Type", "application/json; charset=UTF-8");
        }};

        Map<String,Map<String,String>> headersAndBody = new HashMap<>();
        headersAndBody.put("headers", hMap);
        headersAndBody.put("body", json.dumps(jrd.export()));

        return headersAndBody;
    }

    public String discoveryQuery(String resource) throws URISyntaxException, WebFingerError {
        logger.debug("Looking for OIDC OP for '" + resource + "'");
        String url = this.query(resource, Arrays.asList(OIC_ISSUER));
        HttpResponse response = this.httpd(url, true);
        int statusCode = response.getStatusCode();
        Map<String,Object> hMap = new HashMap<>();
        if(statusCode == 200) {
            if(this.events != null) {
                hMap.put("Response", response.getResponseHeader());
                this.events.add(hMap);
            }

            this.jrd = load(response.getResponseHeader());
            if(this.events != null) {
                hMap = new HashMap<>();
                hMap.put("JRD Response", this.jrd);
                this.events.add(hMap);
            }
            for(Object link : this.jrd.getcParam().get("links")) {
                if(link.getRel().equals(OIC_ISSUER)) {
                    if(!link.getHRef().startsWith("https://")) {
                        throw new WebFingerError("Must be a HTTPS href");
                    }
                    return link.getHRef();
                }
            }
            return null;
        } else if(statusCode == 301 || statusCode == 302 || statusCode == 307) {
            return this.discoveryQuery(response.getResponseHeader("location"));
        } else {
            throw new WebFingerError("Status code is: " + statusCode);
        }
    }

    public String response(String subject, String base, Map<String,Object> args) throws NoSuchFieldException, IllegalAccessException {
        this.jrd = new JRD();
        this.jrd.setSubject(subject);
        Base.link.put("rel", OIC_ISSUER);
        Base.link.put("href", base);
        this.jrd.setLinks(Arrays.asList(Base.link));
        for(String key : args.keySet()) {
            this.jrd.getClass().getField(key).set(key, args.get(key));
        }
        return json.dumps(this.jrd.export());
    }
}
