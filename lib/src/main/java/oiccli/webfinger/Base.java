package oiccli.webfinger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import oiccli.exceptions.ValueError;
import org.junit.Assert;

public class Base {

    private Map<String, Object> ava;
    private Map<String, HashMap<String, List<Base>>> cParams;
    static final Map<String, Object> link = new HashMap<String, Object>() {{
        put("rel", new HashMap<String, Object>() {{
            put("type", String.class);
            put("required", true);
        }});
        put("type", new HashMap<String, Object>() {{
            put("type", String.class);
            put("required", false);
        }});
        put("href", new HashMap<String, Object>() {{
            put("type", String.class);
            put("required", false);
        }});
        put("titles", new HashMap<String, Object>() {{
            put("type", Map.class);
            put("required", false);
        }});
        put("properties", new HashMap<String, Object>() {{
            put("type", Map.class);
            put("required", false);
        }});
    }};

    public Base(Map<String, Object> hMap) {
        ava = new HashMap<>();
        if (hMap != null) {
            this.load(hMap);
        }
        cParams = new HashMap<>();
    }

    public void setItem(String key, List<String> value) {
        HashMap<String, List<Object>> spec = this.cParams.get(key);
        if (spec == null) {
            spec = new HashMap<String, List<Object>>() {{
                put("type", Arrays.<Object>asList(this.toString()));
                put("isRequired", Arrays.<Object>asList(false));
            }};
        }

        List<Object> types = spec.get("type");
        Object t1, t2;
        if (types != null && types.size() == 2) {
            t1 = types.get(0);
            t2 = types.get(1);
        } else {
            throw new IllegalArgumentException("'Type' should have returned 2 values");
        }

        if (t1.getClass().equals(List.class)) {
            List<Object> result = new ArrayList<>();
            if (t2.equals(link)) {
                for (String index : value) {
                    result.add(link.get(index));
                }
            } else {
                for (String index : value) {
                    Assert.assertTrue(index instanceof t2);
                    result.add(index);
                }
            }
            ava.put(key, result);
        }
    }

    public void load(Map<String, List<String>> hMap) throws ValueError {
        for (String key : this.cParams.keySet()) {
            if (!hMap.containsKey(key) && cParams.get(key).get("required")) {
                throw new ValueError("Required attribute " + key + " missing");
            }
        }

        for (String key : hMap.keySet()) {
            if (!hMap.get(key).equals("") || !hMap.get(key).isEmpty()) {
                setItem(key, hMap.get(key));
            }
        }
    }

    public Map<String, HashMap<String, String>> dump() {
        Map<String, HashMap<String, String>> result = new HashMap<>();
        List<Base> list = new ArrayList<>();
        for (String key : this.ava.keySet()) {
            list = this.cParams.get(key).get("type");

            if (list != null && list.size() == 2 && (list.get(0) instanceof List) && (list.get(1) instanceof Map)) {
                List<Base> sRes = new ArrayList(list);
                for (Base index : list) {
                    sRes.add(index.dump());
                }
                list = sRes;
            }
            result.put(key, this.cParams.get(key));
        }

        return result;
    }
}
