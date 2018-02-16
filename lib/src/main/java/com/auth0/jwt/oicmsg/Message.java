package com.auth0.jwt.oicmsg;

import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.oicmsg.exceptions.MessageException;
import com.auth0.jwt.oicmsg.exceptions.MissingRequiredAttribute;
import com.auth0.jwt.oicmsg.exceptions.OicMsgError;
import com.auth0.jwt.oicmsg.exceptions.TooManyValues;
import com.google.common.base.Joiner;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.omg.CORBA.NameValuePair;

public class Message {

    private Map<String, Object> dict;
    private JWT jwt;
    private JWSHeader jwsHeader;
    private JWEHeader jweHeader;
    private boolean lax;
    private boolean shouldVerifySSL;
    public Map<String,Tuple5> claims;
    private Map<String,Object> cDefault;
    public Map<String,List> cAllowedValues;
    public static Tuple5 SINGLE_REQUIRED_STRING = new Tuple5(String.class, true, null, null, false);
    public static Tuple5 SINGLE_OPTIONAL_STRING = new Tuple5(String.class, false, null, null, false);
    public static Tuple5 REQUIRED_LIST_OF_STRINGS = new Tuple5(Arrays.asList(String.class), true, listSerializer, listDeserializer, false);
    public static Tuple5 OPTIONAL_LIST_OF_STRINGS = new Tuple5(Arrays.asList(String.class), false, listSerializer, listDeserializer, false);
    public static Tuple5 SINGLE_OPTIONAL_BOOLEAN = new Tuple5(Arrays.asList(Boolean.class), false, null, null, false);
    public static Tuple5 OPTIONAL_ADDRESS = new Tuple5(Message.class, false, msgSer, addressDer, false);
    public static Tuple5 OPTIONAL_MESSAGE = new Tuple5(Message.class, false, msgSer, msgDer, false);
    public static Tuple5 SINGLE_OPTIONAL_INT = new Tuple5(Integer.class, false, null, null, false);
    public static Tuple5 SINGLE_REQUIRED_INT = new Tuple5(Integer.class, true, null, null, false);
    public static Tuple5 OPTIONAL_LIST_OF_SP_SEP_STRINGS = new Tuple5(Arrays.asList(String.class), false, spSepListSerializer, spSepListDeserializer, false);

    public Message(Map<String,Object> kwargs) {
        this.dict = new HashMap<>(cDefault);
        this.lax = false;
        this.jwt = null;
        this.jwsHeader = null;
        this.jweHeader = null;
        this.fromDict(kwargs);
        this.shouldVerifySSL = true;
    }

    public Message() {
    }

    public String toUrlEncoded(int lev) throws MissingRequiredAttribute, UnsupportedEncodingException {
        if(!this.lax) {
            Tuple5 tuple5;
            for(String key : this.claims.keySet()) {
                tuple5 = claims.get(key);
                if(tuple5.getVRequired() && !this.cDefault.containsKey(key)) {
                    throw new MissingRequiredAttribute("missing attribute: " + key);
                }
            }
        }

        List<Tuple> params = new ArrayList<>();
        String[] splitArgs;
        Tuple5 tuple5 = new Tuple5();
        for(String key : this.cDefault.keySet()) {
            if(!cDefault.containsKey(key)) {
                if(key.contains("#")) {
                    splitArgs = key.split("#");
                    tuple5 = claims.get(splitArgs[0]);
                } else if(key.contains("*")){
                    tuple5 = claims.get("*");
                } else {
                    tuple5.setVSer(null);
                    tuple5.setVNullAllowed(false);
                }
            }

            Object value = cDefault.get(key);
            if(value == null && !tuple5.getVNullAllowed()) {
                continue;
            } else if(value instanceof String) {
                params.add(new Tuple(key, (String) value));
            } else if(value instanceof List) {
                if(tuple5.getVSer() != null) {
                    params.add(new Tuple(key, ser(value, "urlencoded", lev)));
                } else {
                    List list = (List) value;
                    for(Object item : list) {
                        params.add(new Tuple(key, (String) item));
                    }
                }
            } else if(value instanceof Message) {
                value = json.dumps(ser(value, "dict", lev+1));
                params.add(new Tuple(key, value));
            } else if(value == null) {
                params.add(new Tuple(key, value));
            } else {
                params.add(new Tuple(key, ser(value, lev)));
            }
        }
        return urlencode(params);
    }

    public Message fromUrlEncoded(List<String> urlEncoded) throws URISyntaxException, TooManyValues {
        String urlEncodedString = urlEncoded.get(0);

        List<NameValuePair> params = URLEncodedUtils.parse(new URI(urlEncodedString), "UTF-8");

        Tuple5 tuple5;
        String[] splitArgs;
        String key;
        for(NameValuePair param : params) {
            key = param.id;
            tuple5 = this.claims.get(key);
            if(tuple5 == null) {
                if(key.contains("#")) {
                    splitArgs = key.split("#");
                    tuple5 = claims.get(splitArgs[0]);
                } else if(key.contains("*")){
                    tuple5 = claims.get("*");
                } else {
                    if(((List) param.value).size() == 1) {
                        cDefault.put(key, ((List) param.value).get(0));
                        continue;
                    }
                }

            }

            if(tuple5.getvType() != null && tuple5.getvType() == List.class) {
                if(tuple5.getVDSer() != null) {
                    this.cDefault.put(key, tuple5.getVDSer(((List) param.value).get(0), "urlencoded"));
                } else {
                    this.cDefault.put(key, ((List) param.value));
                }
            } else {
                Object value = ((List) param.value).get(0);
                if(((List) param.value).size() == 1) {
                    if(tuple5.getVDSer() != null) {
                        this.cDefault.put(key, tuple5.getVDSer(value, "urlencoded"));
                    } else if(value instanceof tuple5.getvType()) {
                        this.cDefault.put(key, value);
                    }
                } else {
                    throw new TooManyValues(key);
                }
            }
        }

        return this;
    }

    public Object msgSer(Object inst, String sFormat, int lev) throws MessageException, OicMsgError {
        List<String> sFormats = Arrays.asList("urlencoded", "json");
        Object res;
        if(sFormats.contains(sFormat)) {
            if(inst instanceof Map) {
                if(sFormat.equals("json")) {
                    res = json.dumps(inst);
                } else {
                    Map<String,String> map = (Map<String, String>) inst;
                    for(String key  : map.keySet()) {
                        map.put(URLEncoder.encode(key), URLEncoder.encode(map.get(key)));
                    }
                    res = map;
                }
            } else if(inst instanceof Message) {
                res = ((Message) inst).serialize(sFormat, lev);
            } else {
                res = inst;
            }
        } else if(sFormat.equals("dict")) {
            if(inst instanceof Message) {
                res = ((Message) inst).serialize(sFormat, lev);
            } else if(inst instanceof Map || inst instanceof String) {
                res = inst;
            } else {
                throw new MessageException("Wrong type: " + inst.getClass());
            }
        } else {
            throw new OicMsgError("Unknown sFormat: " + inst);
        }

        return res;
    }

    private String urlencode(List<Tuple> params) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for(Tuple param : params){
            if(sb.length() > 0){
                sb.append('&');
            }
            sb.append(URLEncoder.encode((String) param.getA(), "UTF-8")).append('=').append(URLEncoder.encode((String) param.getB(), "UTF-8"));
        }

        return sb.toString();
    }

    public Collection<Object> getValues() {
        return this.dict.values();
    }

    public Map<String, String> serialize(String sFormat, int lev) {
        return null;
    }

    public Map<String, Tuple5> getClaims() {
        return claims;
    }

    public void updateClaims(Map<String, Tuple5> claims) {
        for(String key : claims.keySet()) {
            this.claims.put(key, claims.get(key));
        }
    }

    public void setClaims(Map<String, Tuple5> claims) {
        this.claims = claims;
    }

    public Map<String, List> getcAllowedValues() {
        return cAllowedValues;
    }

    public void setcAllowedValues(Map<String, List> cAllowedValues) {
        this.cAllowedValues = cAllowedValues;
    }

    public void updatecAllowedValues(Map<String, List> claims) {
        for(String key : claims.keySet()) {
            this.cAllowedValues.put(key, claims.get(key));
        }
    }

    private void fromDict(Map<String, Object> kwargs) {
    }

    public Map<String,Object> getDict() {
        return dict;
    }

    public void addDict(Map<String, Object> claims) {
        for(String key : claims.keySet()) {
            this.dict.put(key, claims.get(key));
        }
    }

    public void setDict(Map<String, Object> claims) {
        this.dict = claims;
    }

    public static JWT toJWT(Key key, String algorithm, int lev) {
    }

    public boolean verify(Map<String,Object> kwargs) throws Exception {

    }

    public String spSepListSerializer(List<String> vals) {
        if(vals != null && vals.size() == 1) {
            return vals.get(0);
        } else {
            Joiner joiner = Joiner.on(" ").skipNulls();
            return joiner.join(vals);
        }
    }

    public List<String> spSepListDeserializer(List<String> vals) {
        if(vals != null && vals.size() == 1) {
            return Arrays.asList(vals.get(0).split(" "));
        } else {
            return vals;
        }
    }
}
