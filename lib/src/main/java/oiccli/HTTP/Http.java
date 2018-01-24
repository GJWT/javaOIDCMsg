package oiccli.HTTP;

import java.util.HashMap;
import java.util.Map;

public class Http {

    private String caCerts;
    private Map<String, Object> requestArgs;
    private KeyJar keyJar;
    private FileCookieJar cookieJar;
    private Object events;
    private Object reqCallback;

    public Http(String caCerts, boolean shouldVerifySSL, KeyJar keyjar, String clientCert) {
        this.caCerts = caCerts;
        this.requestArgs = new HashMap() {{
            put("allowRedirects", false);
        }};
        this.keyJar = keyjar; //or KeyJar(verify_ssl=verify_ssl)
        //this.cookiejar = FileCookieJar()
        if (caCerts != null) {
            if (!shouldVerifySSL) {
                throw new ValueError("conflict: ca_certs defined, but verify_ssl is False");
            }
            this.requestArgs.put("verify", caCerts);
        } else if (shouldVerifySSL) {
            this.requestArgs.put("verify", true);
        } else {
            this.requestArgs.put("verify", false);
        }
        this.events = null;
        this.reqCallback = null;

        if (clientCert != null) {
            this.requestArgs.put("cert", clientCert);
        }
    }

    public Map<String, String> getCookies() {
        Map<String, String> cookiesMap = new HashMap<>();
        for (cookieJar.getCookies().)


        {
            return cookiesMap;
        }
    }
}
