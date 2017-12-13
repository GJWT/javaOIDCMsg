// Copyright (c) 2017 The Authors of 'JWTS for Java'
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package com.auth0.jwt.algorithms;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.creators.EncodeType;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.Payload;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;

import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

class ECDSAAlgorithm extends Algorithm {

    private final ECDSAKeyProvider keyProvider;
    private final CryptoHelper crypto;
    private final int ecNumberSize;

    //Visible for testing
    ECDSAAlgorithm(CryptoHelper crypto, String id, String algorithm, int ecNumberSize, ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
        this.ecNumberSize = ecNumberSize;
    }

    ECDSAAlgorithm(String id, String algorithm, int ecNumberSize, ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, ecNumberSize, keyProvider);
    }

    @Override
    public void verify(DecodedJWT jwt, EncodeType encodeType) throws Exception {
        byte[] contentBytes = String.format("%s.%s", jwt.getHeader(), jwt.getPayload()).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = null;
        String signature = jwt.getSignature();
        String urlDecoded = null;
        switch (encodeType) {
            case Base16:
                urlDecoded = URLDecoder.decode(signature, "UTF-8");
                signatureBytes = Hex.decodeHex(urlDecoded);
                break;
            case Base32:
                Base32 base32 = new Base32();
                urlDecoded = URLDecoder.decode(signature, "UTF-8");
                signatureBytes = base32.decode(urlDecoded);
                break;
            case Base64:
                signatureBytes = Base64.decodeBase64(signature);
                break;
        }

        try {

            //create a http request that gets back a response for the jwks uri and then once you get back the response,
            //parse it to get back the x509 DER string and get the public key from that string
            //from the public key of that string, pass it into verifySignatureFor()
            PublicKey publicKey = null;
            String kid = jwt.getKeyId();
            String algorithm = jwt.getAlgorithm();
            if(kid == null) {
                publicKey = keyProvider.getPublicKeyById(kid);
            } else if(algorithm.equals("RSA")){
                //JwkProvider provider = new UrlJwkProvider("https://sandrino.auth0.com/.well-known/jwks.json");
                JwkProvider provider = new UrlJwkProvider(new File("/Users/jdahmubed/documents/jwksRSA.json").toURI().toURL());//"file:///);
                Jwk jwk = provider.get(kid);
                publicKey = jwk.getPublicKey();
            } /*else if(algorithm.contains("ES")) {
               // JSONParser parser = new JSONParser();
               // JSONArray a = (JSONArray) parser.parse(new FileReader("/Users/jdahmubed/documents/jwks.json"));

                JsonObject gsonObject = new JsonObject();


                JsonParser parser = new JsonParser();
                JsonElement jsonElement = parser.parse(new FileReader("/Users/jdahmubed/documents/jwks.json"));
                gsonObject = jsonElement.getAsJsonObject();

                JSONObject jsonObject = new JSONObject();
                for(String key : gsonObject.keySet()) {
                    jsonObject.put(key, gsonObject.get(key));
                }
                jsonObject.put("alg", "ES256");
                JWSHeader jwsHeader = JWSHeader.parse(jsonObject);

                JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
                header.setJWKURL(new File("/Users/jdahmubed/documents/jwks.json").toURI().toURL());
                List<com.nimbusds.jose.util.Base64> list = header.getX509CertChain();
                System.out.print(list);
            }*/

            if (publicKey == null) {
                throw new IllegalStateException("The given Public Key is null.");
            }
            //pass in publicKey from x509 or the current key (look up)
            boolean valid = crypto.verifySignatureFor(getDescription(), publicKey, contentBytes, JOSEToDER(signatureBytes));

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            ECPrivateKey privateKey = keyProvider.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            byte[] signature = crypto.createSignatureFor(getDescription(), privateKey, contentBytes);
            return DERToJOSE(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    @Override
    public String getSigningKeyId() {
        return keyProvider.getPrivateKeyId();
    }

    //Visible for testing
    byte[] DERToJOSE(byte[] derSignature) throws SignatureException {
        // DER Structure: http://crypto.stackexchange.com/a/1797
        boolean derEncoded = derSignature[0] == 0x30 && derSignature.length != ecNumberSize * 2;
        if (!derEncoded) {
            throw new SignatureException("Invalid DER signature format.");
        }

        final byte[] joseSignature = new byte[ecNumberSize * 2];

        //Skip 0x30
        int offset = 1;
        if (derSignature[1] == (byte) 0x81) {
            //Skip sign
            offset++;
        }

        //Convert to unsigned. Should match DER length - offset
        int encodedLength = derSignature[offset++] & 0xff;
        if (encodedLength != derSignature.length - offset) {
            throw new SignatureException("Invalid DER signature format.");
        }

        //Skip 0x02
        offset++;

        //Obtain R number length (Includes padding) and skip it
        int rLength = derSignature[offset++];
        if (rLength > ecNumberSize + 1) {
            throw new SignatureException("Invalid DER signature format.");
        }
        int rPadding = ecNumberSize - rLength;
        //Retrieve R number
        System.arraycopy(derSignature, offset + Math.max(-rPadding, 0), joseSignature, Math.max(rPadding, 0), rLength + Math.min(rPadding, 0));

        //Skip R number and 0x02
        offset += rLength + 1;

        //Obtain S number length. (Includes padding)
        int sLength = derSignature[offset++];
        if (sLength > ecNumberSize + 1) {
            throw new SignatureException("Invalid DER signature format.");
        }
        int sPadding = ecNumberSize - sLength;
        //Retrieve R number
        System.arraycopy(derSignature, offset + Math.max(-sPadding, 0), joseSignature, ecNumberSize + Math.max(sPadding, 0), sLength + Math.min(sPadding, 0));

        return joseSignature;
    }

    //Visible for testing
    byte[] JOSEToDER(byte[] joseSignature) throws SignatureException {
        if (joseSignature.length != ecNumberSize * 2) {
            throw new SignatureException("Invalid JOSE signature format.");
        }

        // Retrieve R and S number's length and padding.
        int rPadding = countPadding(joseSignature, 0, ecNumberSize);
        int sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
        int rLength = ecNumberSize - rPadding;
        int sLength = ecNumberSize - sPadding;

        int length = 2 + rLength + 2 + sLength;
        if (length > 255) {
            throw new SignatureException("Invalid JOSE signature format.");
        }

        final byte[] derSignature;
        int offset;
        if (length > 0x7f) {
            derSignature = new byte[3 + length];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            offset = 1;
        }

        // DER Structure: http://crypto.stackexchange.com/a/1797
        // Header with signature length info
        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) (length & 0xff);

        // Header with "min R" number length
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) rLength;

        // R number
        if (rPadding < 0) {
            //Sign
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, 0, derSignature, offset, ecNumberSize);
            offset += ecNumberSize;
        } else {
            int copyLength = Math.min(ecNumberSize, rLength);
            System.arraycopy(joseSignature, rPadding, derSignature, offset, copyLength);
            offset += copyLength;
        }

        // Header with "min S" number length
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) sLength;

        // S number
        if (sPadding < 0) {
            //Sign
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, ecNumberSize, derSignature, offset, ecNumberSize);
        } else {
            System.arraycopy(joseSignature, ecNumberSize + sPadding, derSignature, offset, Math.min(ecNumberSize, sLength));
        }

        return derSignature;
    }

    private int countPadding(byte[] bytes, int fromIndex, int toIndex) {
        int padding = 0;
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
            padding++;
        }
        return (bytes[fromIndex + padding] & 0xff) > 0x7f ? padding - 1 : padding;
    }

    //Visible for testing
    static ECDSAKeyProvider providerForKeys(final ECPublicKey publicKey, final ECPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }

        return new ECDSAKeyProvider() {
            @Override
            public ECPublicKey getPublicKeyById(String keyId) {
                return publicKey;
            }

            @Override
            public ECPrivateKey getPrivateKey() {
                return privateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }
}
