package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.Service;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.MissingRequiredAttribute;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.auth0.jwt.oiccli.exceptions.WebFingerError;
import com.auth0.jwt.oiccli.responses.ErrorResponse;
import com.auth0.jwt.oiccli.webfinger.JRD;
import com.google.common.base.Strings;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WebFinger extends Service{

    private Message messageType;
    private JRD responseCls;
    private ErrorResponse errorResponse;
    private boolean isSynchronous;
    private String request;
    private String httpMethod;
    private String responseBodyType;
    private com.auth0.jwt.oiccli.webfinger.WebFinger webFinger;
    private static final String OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";

    public WebFinger(String httpLib, KeyJar keyJar, String clientAuthenticationMethod,
                     Map<String,String> conf) throws NoSuchFieldException, IllegalAccessException {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);
        this.webFinger = new com.auth0.jwt.oiccli.webfinger.WebFinger(httpLib, OIC_ISSUER);
        this.postParseResponse.add(this.wf_post_parse_response);
    }

    public JRD wfPostParseResponse(JRD response, ClientInfo clientInfo) throws MissingRequiredAttribute, ValueError {
        List<Map<String,String>> links = response.getLinks();
        if(links == null) {
            throw new MissingRequiredAttribute("links is null");
        } else {
            String href = null;
            for(Map<String,String> link : links) {
                if(link.get("rel").equals(OIC_ISSUER)) {
                    href = link.get("href");
                }
                if(Strings.isNullOrEmpty(this.getConfigurationAttribute("allowHttpLinks"))) {
                    if(!Strings.isNullOrEmpty(href) && href.startsWith("http://")) {
                        throw new ValueError("http link not allowed (" + href + ")");
                    }
                }
                clientInfo.setIssuer(link.get("href"));
                break;
            }
        }

        return response;
    }

    public Map<String, String> requestInfo(ClientInfo clientInfo, String method, Map<String,String> requestArgs, boolean lax,
                                           Map<String,String> args) throws MissingRequiredAttribute, URISyntaxException, WebFingerError {
        String resource = args.get("resource");
        if(Strings.isNullOrEmpty(resource)) {
            resource = (String) clientInfo.getConfig().get("resource").get("resource");
            if(Strings.isNullOrEmpty(resource)) {
                throw new MissingRequiredAttribute("resource is null or empty");
            }
        }

        Map<String,String> hMap = new HashMap<>();
        hMap.put("uri", this.webFinger.query(resource));

        return hMap;
    }
}
