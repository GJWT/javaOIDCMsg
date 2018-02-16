package com.auth0.jwt.oicmsg.oic;

import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.oicmsg.JWSHeader;
import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import com.auth0.jwt.oicmsg.exceptions.EXPError;
import com.auth0.jwt.oicmsg.exceptions.IATError;
import com.auth0.jwt.oicmsg.exceptions.IssuerMismatch;
import com.auth0.jwt.oicmsg.exceptions.MissingRequiredAttribute;
import com.auth0.jwt.oicmsg.exceptions.NotForMe;
import com.auth0.jwt.oicmsg.exceptions.ValueError;
import com.auth0.jwt.oicmsg.exceptions.VerificationError;
import com.google.common.base.Strings;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class IdToken extends OpenIdSchema{

    private String atHash;
    private String cHash;
    private String jti;
    private String issuer;
    private String azp;
    private long iat;
    private List<String> audience;
    private Map<String,String> hashTable;
    private static final int NONCE_STORAGE_TIME = 4 * 3600;

    public IdToken() {
        Map<String,Tuple5> claims = getClaims();
        claims.put("iss", SINGLE_REQUIRED_STRING);
        claims.put("sub", SINGLE_REQUIRED_STRING);
        claims.put("aud", REQUIRED_LIST_OF_STRINGS);
        claims.put("exp", SINGLE_REQUIRED_INT);
        claims.put("iat", SINGLE_REQUIRED_INT);
        claims.put("authTime", SINGLE_OPTIONAL_INT);
        claims.put("nonce", SINGLE_OPTIONAL_STRING);
        claims.put("atHash", SINGLE_OPTIONAL_STRING);
        claims.put("cHash", SINGLE_OPTIONAL_STRING);
        claims.put("acr", SINGLE_OPTIONAL_STRING);
        claims.put("amr", OPTIONAL_LIST_OF_STRINGS);
        claims.put("azp", SINGLE_OPTIONAL_STRING);
        claims.put("subJwk", SINGLE_OPTIONAL_STRING);
        updateClaims(claims);

        hashTable = new HashMap<String,String>() {{
           put("accessToken", "atHash");
           put("code", "cHash");
        }};
    }

    public void valHash(String algorithm) throws Exception {
        String hashAlgorithm = "HS" + algorithm.substring(algorithm.length()-3);
        String param;
        for(String attribute : hashTable.keySet()) {
            param = hashTable.get(attribute);
            this.getClass().getField(param).set(param, JWS.leftHash(this.getClass().getField(attribute).toString(), hashAlgorithm));
        }
    }

    public void packInit(int lifetime) throws Exception{
        this.getClass().getField("iat").set("iat", System.currentTimeMillis());
        if(lifetime != 0) {
            this.getClass().getField("exp").set("exp", this.getClass().getField("iat").getInt(this) + lifetime);
        }
    }

    public void packInit() throws Exception{
        packInit(0);
    }

    public void pack(String algorithm, Map<String,Object> args) throws Exception{
        this.valHash(algorithm);
        if(args.containsKey("lifetime")) {
            this.packInit((Integer) args.get("lifetime"));
        } else {
            this.packInit();
        }

        String jti;
        if(this.cParam.containsKey("jti")) {
            if(args.containsKey("jti")) {
                if(args.get("jti") instanceof String) {
                    jti = (String) args.get("jti");
                } else {
                    throw new ValueError("Jti should be a string");
                }
            } else {
                jti = getRandomHexString(15);
            }

            this.setJti(jti);
        }
    }

    public boolean verify(Map<String,Object> args) throws Exception {
        new IdToken().verify(args);

        if(args.get("issuer") instanceof String && !Strings.isNullOrEmpty((String) args.get("issuer")) && !args.get("issuer").equals(this.getIssuer())) {
            throw new IssuerMismatch(args.get("issuer") + " != " + this.getIssuer());
        }

        if(this.getAudience() != null && !this.getAudience().isEmpty()) {
            if(args.containsKey("clientId")) {
                if(!this.getAudience().contains(args.get("clientId"))) {
                    throw new NotForMe(args.get("clientId") + " not in aud: " + this.getAudience());
                }
            }

            if(this.getAudience().size() > 1) {
                if(!Strings.isNullOrEmpty(this.getAzp())) {
                    if(!this.getAudience().contains(this.getAzp())) {
                        throw new VerificationError("Mismatch between azp and aud claims");
                    }
                } else {
                    throw new VerificationError("azp missing");
                }
            }
        }

        if(!Strings.isNullOrEmpty(this.getAzp())) {
            if(args.containsKey("clientId")) {
                if(args.get("clientId") instanceof String && !Strings.isNullOrEmpty((String) args.get("clientId")) && !args.get("clientId").equals(this.getAzp())) {
                    throw new NotForMe(args.get("clientId") + " != azp: " + this.getAzp());
                }
            }
        }

        long now = System.currentTimeMillis();

        Integer skewInteger = (Integer) args.get("skew");
        int skew;
        if(skewInteger != null) {
            skew = skewInteger.intValue();
        } else {
            skew = 0;
        }

        Integer expInteger = (Integer) args.get("exp");
        int exp;
        if(expInteger != null) {
            exp = expInteger.intValue();
        } else {
            throw new MissingRequiredAttribute("exp");
        }

        if(now - skew > exp) {
            throw new EXPError("Invalid expiration time");
        }

        Integer nonceStorageTimeInteger = (Integer) args.get("nonceStorageTime");
        int nonceStorageTime;
        if(nonceStorageTimeInteger != null) {
            nonceStorageTime = nonceStorageTimeInteger.intValue();
        } else {
            nonceStorageTime = NONCE_STORAGE_TIME;
        }

        long iat = this.getIat();
        if(iat + nonceStorageTime < (now - skew)) {
            throw new IATError("Issued too long ago");
        }

        return true;
    }

    public JWT toJWT(Key key, String algorithm, int lev, int lifetime) {
        this.pack(algorithm, lifetime);
        return Message.toJWT(key, algorithm,lev);
    }

    private String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
    }

    public IdToken fromJWT(String idToken, Map<String, Object> args) {
    }

    public String getJwsHeader(String alg) {

    }

    public String getAtHash() {
        return atHash;
    }

    public String getCHash() {
        return cHash;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getIssuer() {
        return issuer;
    }

    public List<String> getAudience() {
        return audience;
    }

    public String getAzp() {
        return azp;
    }

    public long getIat() {
        return iat;
    }
}
