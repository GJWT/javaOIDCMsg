package com.auth0.jwt.algorithms;

import com.auth0.jwt.creators.EncodeType;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(DecodedJWT jwt, EncodeType encodeType) throws Exception {
        byte[] signatureBytes = null;
        String signature = jwt.getSignature();
        switch (encodeType) {
            case Base16:
                signatureBytes = Hex.decodeHex(signature);
                break;
            case Base32: {
                Base32 base32 = new Base32();
                signatureBytes = base32.decode(signature);
                break;
            }
            case Base64:
                signatureBytes = Base64.decodeBase64(signature);
                break;
            case JsonEncode:
                break;
            //token = jwtCreator.signJsonEncode();
        }
        if (signatureBytes.length > 0) {
            throw new SignatureVerificationException(this);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }
}
