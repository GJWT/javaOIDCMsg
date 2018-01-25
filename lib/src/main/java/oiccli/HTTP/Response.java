package oiccli.HTTP;

import com.auth0.jwt.creators.Message;
import com.google.common.base.Strings;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class Response {

    private static final List<Integer> successfulCodes =
            Arrays.asList(200, 201, 202, 203, 204, 205, 206);
    private static Map<String, String> corsHeaders = new
            HashMap<String, String>() {{
                put("Access-Control-Allow-Origin", "*");
                put("Access-Control-Allow-Methods", "GET");
                put("Access-Control-Allow-Headers", "Authorization");
            }};
    private String status = "200 OK";
    private String contentType = "text/html";
    private Object template;
    private Object makoTemplate;
    private Object makoLookup;
    private Message message;
    private List<Map<String, String>> headers;

    public Response(Message message, Map<String, Object> args) {
        this.status = args.get("status");
        this.response = args.get("response");
        this.template = args.get("template");
        this.makoTemplate = args.get("makoTemplate");
        this.makoLookup = args.get("templateLookup");

        this.message = message;
        this.headers = new ArrayList<>();
        this.headers.add(args.get("headers"), new List<>());
        this.contentType = args.get("content");

    }

    private List<String> getResponse(String message, Map<String, String> args) {
        if (!Strings.isNullOrEmpty(message)) {
            if (message.contains("<script>")) {
                message = message.replace("<script>", "&lt;script&gt;").replace(
                        "</script>", "&lt;/script&gt;");
            }
        }

        if (this.template != null) {
            for (Map<String, String> hMap : headers) {
                if ("application/json".equals(hMap.get("Content-type"))) {
                    return Arrays.asList(message);
                } else {
                    //return [str(self.template % message).encode("utf-8")]
                }
            }
        } else if (this.makoLookup != null && this.makoTemplate != null) {
            args.put("message", message);
            Object mte = this.makoLookup.getTemplate(this.makoTemplate);
            return Arrays.asList(mte.render(args));
        } else {
            for (String type : this._c_types()) {
                if (type.startsWith("image/") || type.equals("application/x-gzip")) {
                    return Arrays.asList(message);
                }
            }
        }


    }

    public Map<String, Object> info() {
        Map<String, Object> hMap = new HashMap<String, Object>() {{
            put("status", this.status);
            put("headers", this.headers);
            put("message", this.message);
        }};

        return hMap;
    }

    public void addHeader(Map<String, String> value) {
        this.headers.add(value);
    }

    public Response reply(Map<String, String> args) {
        return this.response(message, args);
    }

    public List<String> cTypes() {
        List<String> cTypes = new ArrayList<>();
        Iterator it;
        Map.Entry pair;
        for (Map<String, String> index : this.headers) {
            it = index.entrySet().iterator();
            while (it.hasNext()) {
                pair = (Map.Entry) it.next();
                if (((String) pair.getKey()).equals("Content-type")) {
                    cTypes.add((String) pair.getValue());
                }
            }
        }
    }


}
