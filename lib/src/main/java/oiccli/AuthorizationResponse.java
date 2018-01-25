package oiccli;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import oiccli.exceptions.AtHashError;
import oiccli.exceptions.CHashError;
import oiccli.exceptions.MissingRequiredAttribute;

public class AuthorizationResponse {

    private String code;
    private String accessToken;
    private String tokenType;
    private String idToken;

    public boolean verify(Map<String, String> args) throws MissingRequiredAttribute {
        //super(AuthorizationResponse, self).verify(**kwargs)

        if (this.contains("aud")) {
            if (args.containsKey("clientId")) {
                if (!this.getAudience().contains(args.get("clientId"))) {
                    return false;
                }
            }
        }

        if (this.contains("idToken")) {
            Map<String, String> argsTemp = new HashMap<>();
            for (String arg : Arrays.asList("key", "keyjar", "algs", "sender")) {
                argsTemp.put(arg, args.get(arg));
            }

            /*
            idt = IdToken().from_jwt(str(self["id_token"]), **args)
            if not idt.verify(**kwargs):
                raise VerificationError("Could not verify id_token", idt)

            _alg = idt.jws_header["alg"]
             */

            String hFunction = "HS" + algorithm.substring(0, algorithm.length() - 3);
            if (this.getAccessToken() != null) {
                if (this.idt.getAtHash() == null) {
                    throw new MissingRequiredAttribute("Missing at_hash property" +
                            idToken.toString());
                }

                if (idt.getAtHash() != jws.leftHash(this.getAccessToken(), hFunction)) {
                    throw new AtHashError(
                            "Failed to verify access_token hash " + idt.toString());
                }
            }

            if (this.getCode() != null) {
                if (this.idt.getCHash() == null) {
                    throw new MissingRequiredAttribute("Missing cHash property" +
                            idToken.toString());
                }
                if (idt.getCHash() != jws.leftHash(this.getCode(), hFunction)) {
                    throw new CHashError("Failed to verify code hash " + idt.toString());
                }
            }

            this.setVerifiedIdToken(idt);
        }
        return true;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }
}
