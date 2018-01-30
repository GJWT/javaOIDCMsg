package oiccli;

import java.util.HashMap;
import java.util.Map;

public class FakeResponse {

    private Map<String,String> headers;
    private String text;

    public FakeResponse(String header) {
        Map<String,String> headersTemp = new HashMap<>();
        headers.put("contentType", header);
        this.headers = headersTemp;
        this.text = "TEST_RESPONSE";
    }
}
