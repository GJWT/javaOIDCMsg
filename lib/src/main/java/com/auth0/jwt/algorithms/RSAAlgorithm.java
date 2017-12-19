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
import com.auth0.jwt.creators.JWTCreator;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

class RSAAlgorithm extends Algorithm {

    private final RSAKeyProvider keyProvider;
    private final CryptoHelper crypto;
    public static byte[] bytesAfterBeingDecoded;

    //Visible for testing
    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, keyProvider);
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
                System.out.println("signature bytes after being decoded: " + Arrays.toString(signatureBytes));
                bytesAfterBeingDecoded = signatureBytes;
                System.out.println("Are they equal? " + Arrays.equals(JWTCreator.bytesBeforeBeingDecoded, bytesAfterBeingDecoded));
                break;
            case Base64:
                signatureBytes = Base64.decodeBase64(signature);
                System.out.println("signature bytes after being decoded: " + Arrays.toString(signatureBytes));
                bytesAfterBeingDecoded = signatureBytes;
                System.out.println("Are they equal? " + Arrays.equals(JWTCreator.bytesBeforeBeingDecoded, bytesAfterBeingDecoded));
                break;
        }

        try {
            String kid = jwt.getKeyId();
            JwkProvider provider = new UrlJwkProvider(new File("./jwksRSA.json").toURI().toURL());
            Jwk jwk = provider.get(kid);
            String cert = jwk.getCertificateChain().get(0);
            try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream("./jwks.cert"), "utf-8"))) {
                writer.write("-----BEGIN CERTIFICATE-----");
                writer.append("\n"+ cert + "\n");
                writer.append("-----END CERTIFICATE-----");
            }

            FileReader file = new FileReader("./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
            PemReader reader = new PemReader(file);
            X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(reader.readPemObject().getContent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(caKeySpec);
            if (publicKey == null) {
                throw new IllegalStateException("The given Public Key is null.");
            }
            boolean valid = crypto.verifySignatureFor(getDescription(), publicKey, contentBytes, signatureBytes);
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
            RSAPrivateKey privateKey = keyProvider.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            return crypto.createSignatureFor(getDescription(), privateKey, contentBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    @Override
    public String getSigningKeyId() {
        return keyProvider.getPrivateKeyId();
    }

    //Visible for testing
    static RSAKeyProvider providerForKeys(final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return privateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }
}
