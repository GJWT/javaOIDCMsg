package oiccli.webfinger;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JRD extends Base{
    private static final Map<String,Object> cParam = new HashMap<String,Object>() {{
        put("expires", new HashMap<String,Object>() {{ put("type", String.class); put("required", false); }});
        put("subject", new HashMap<String,Object>() {{ put("type", String.class); put("required", false); }});
        put("aliases", new HashMap<String,Object>() {{ put("type", Arrays.asList(String.class, List.class)); put("required", false); }});
        put("properties", new HashMap<String,Object>() {{ put("type", Map.class); put("required", false); }});
        put("links", new HashMap<String,Object>() {{ put("type", Arrays.asList(List.class, Map.class)); put("required", false); }});
    }};
    private int expDays;
    private int expSeconds;
    private int expMins;
    private int expHour;
    private int expWeek;

    public JRD(Map<String, Object> hMap, int days, int seconds, int minutes, int hours, int weeks) {
        super(hMap);
        this.expiresIn(days, seconds, minutes, hours, weeks);
    }

    public JRD() {
        this(null,0,0,0,0,0);
    }

    public void expiresIn(int days, int seconds, int minutes, int hours, int weeks) {
        this.expDays = days;
        this.expSeconds = seconds;
        this.expMins = minutes;
        this.expHour = hours;
        this.expWeek = weeks;
    }

    public Map<String, HashMap<String, String>> export() {
        Map<String, HashMap<String, String>> result = dump();
        result.put("expires", inAWhile(this.expDays, this.expSeconds, this.expMins, this.expHour, this.expWeek));
        return result;
    }

    public Map<String,Object> getcParam() {
        return cParam;
    }
}
