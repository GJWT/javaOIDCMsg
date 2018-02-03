package com.auth0.jwt.oiccli.Utils;

import com.auth0.jwt.creators.Message;
import java.util.List;

public class JWE {
    private String kid;
    
    public JWE(Message message, String encryptionAlg, String encryptionEnc) {
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public Message encrypt(List<Key> keys) {
        throw new UnsupportedOperationException();
    }
}
