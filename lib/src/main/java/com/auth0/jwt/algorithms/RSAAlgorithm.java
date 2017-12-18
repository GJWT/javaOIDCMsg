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
            //RSAPublicKey publicKey = keyProvider.getPublicKeyById(jwt.getKeyId());
            /*String kid = jwt.getKeyId();
            JwkProvider provider = new UrlJwkProvider(new File("/Users/jdahmubed/documents/jwksRSA.json").toURI().toURL());
            Jwk jwk = provider.get(kid);
            PublicKey publicKey = jwk.getPublicKey();*/


            String kid = jwt.getKeyId();
            JwkProvider provider = new UrlJwkProvider(new File("./jwksRSA.json").toURI().toURL());
            Jwk jwk = provider.get(kid);
            //String cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE983wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVsWXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0YwIDAQAB";
            /*String cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvUihVNnWYpu3uJmcLy+PBecKu4ziVD7OIeZ/V+tJkXbc5+6OW8G+QDtJKuJkkuxGNLBNmLHbCyXsJ/US3kKkU7/7yK7jfWRNdqAKJdDTVxsWnxlo+/28ScGrAV6wK2bbK8GQBpsYRn1HKGCGceWIBCSqUfI7rwgwDnvqcW5PeivORd4+or5DdhgUMwiV5Vr2fvdcAiQR1CKgMphxO4+OmZ4khpB/HT/xS4FscvfFsSBLM37jBMrnhY5yNKPeHZB2eYvehnnw22NFHJNksa+vVFXL9aJcZWJc/bqqlhlhL8eLdYSR/KA006PSInW8yWtd4IFVKJ1Moa41gCUZL81voQIDAQAB";
            ByteArrayInputStream bytearrayinputstream = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(cert));
            X509Certificate x509certificate;
            x509certificate = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(bytearrayinputstream);
            RSAPublicKey publicKey = (RSAPublicKey)x509certificate.getPublicKey();*/

            //RSAPublicKey publicKey = keyProvider.getPublicKeyById(jwt.getKeyId());

            /*String cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
                    "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
                    "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
                    "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
                    "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
                    "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
                    "YwIDAQAB";*/
            System.out.println("Working Directory = " +
                    System.getProperty("user.dir"));
            String cert = "MIIFQDCCAyigAwIBAgIJAIAQTsRw4XqQMA0GCSqGSIb3DQEBCwUAMDUxCzAJBgNV\n" +
                    "BAYTAlNFMRIwEAYDVQQKDAlDYXRhbG9naXgxEjAQBgNVBAMMCWxvY2FsaG9zdDAe\n" +
                    "Fw0xNzEyMTUxOTE1MjlaFw0xODEyMTUxOTE1MjlaMDUxCzAJBgNVBAYTAlNFMRIw\n" +
                    "EAYDVQQKDAlDYXRhbG9naXgxEjAQBgNVBAMMCWxvY2FsaG9zdDCCAiIwDQYJKoZI\n" +
                    "hvcNAQEBBQADggIPADCCAgoCggIBAKAFR65TGJ87P7Pf0Qyay6lZ00a/BaY04IgQ\n" +
                    "rXCehBpkC8LEOX//pef9FKWYVoa2a5nbw11v62mP6d0s2F+Hxzhlz20IxumYoyY3\n" +
                    "RR19QhA24B16JCYR8gkZjL0VBPzKsZp1Nk48oR1Pn8RmFMps8ERfgmKp9hwXQz4G\n" +
                    "va8tU8b9HTHjbs9716nfxd6lkHWPqrfAx3X+z673K0l9nt8t1Qjm1Xd6mAAz52sH\n" +
                    "F6VBf1DUnHGwaAKP5QztNEtx1bfX8iJHTh2yFkyPUwQwF6+4v+IuvctVK/Swf8Tw\n" +
                    "PqKpsijlgWGtBoW3HSbVP3W/PrXjlF2jsrozFhqmXLVPHhh9dhxtfMxRpCGrhXyh\n" +
                    "URJOqnuIaW4Nz43CYvE17tDgPsdU24nAmwCFx8b7hFCEKPNXkT04YAx9CGrhRblv\n" +
                    "mh9nijDtV3xoHuueV+KLJ+UXyl0Tb2NvsN1WTB8m6A3fkb0CKiOFQPh5x7wUvTEg\n" +
                    "DOZgFLjQ58E+O8ppyDtjaxHA71KRIYyzuob8Z8AhErdlEBBb6WyIvulHhlcDWnIj\n" +
                    "bZ6v7X+pRGJSIJj+tYFgwMuTAgBTkIvohK6uBRU9E8rVPHFZ/0NGtJ66ILN3IEa7\n" +
                    "yKN8h8sretsb67XFujf8lN0+SQZhbyvAjvs6gsM93Asvo+lOPst7pc9O35g8Frkz\n" +
                    "tCzvyUMRAgMBAAGjUzBRMB0GA1UdDgQWBBQYsp8KJs+Rk8GQmUbFxqWklKOC7zAf\n" +
                    "BgNVHSMEGDAWgBQYsp8KJs+Rk8GQmUbFxqWklKOC7zAPBgNVHRMBAf8EBTADAQH/\n" +
                    "MA0GCSqGSIb3DQEBCwUAA4ICAQAfHxNIahFjwIC8jKgT0kFPh752ZjtAD00PUwtM\n" +
                    "RiaMgYTWpZlQkYz0DEGPEbWyRHs0qCfxHhMvDs6selnZRWn/1dFZB0BxEroQCB0o\n" +
                    "oZK5pm0TAICShiAdPyef8VupMZtaKWtir1wh40Lj19vGxI1lcKpCLxA1NihePX7u\n" +
                    "ZCfSAEqLKVpz/4bZd6s7LLlCHmdS4zGLuF0dgoOL38LS30d6WKXc5SgYnFvXtKeV\n" +
                    "n8V4CntRmVY3YMkMtRdujt2MweVVnhuclycwCL7D/zHOAyNAliZqilp2hVtrOYOp\n" +
                    "9K0W9S9t67dLFDra6uIynVyUhCwQ5O4lmx/WEolLwmpSoiPEavOmhTKEqRKUjjkO\n" +
                    "5X8QWxgSpZ+VtR2L7LTHknVXiv0uO8bgwWGTpzvXdUyHFOu+Z1b8sjqh+Z7CkEaz\n" +
                    "3aLq/TjHlPvW0LZk53OwYweZVelbL3ssor+rE8sxb543nlh0rnUNKG+zbNUoM/PS\n" +
                    "FyLQduERK97RZKyeBgjUQ95k865PO9jBeruOF4MMpLF8zLixQdcTWerAjVagafKA\n" +
                    "xltFrB+L3HADG0YZnceQW8d07ROjarm2Wa6tx71sUppqn1cogAoQlIFl3K8lD3gd\n" +
                    "vWLlelJvcre0p4K1LhYHDD4vayJuDV3391dxWX9QQd4HS2k2p0JljUIaUzrn8+fe\n" +
                    "w8h7tQ==";
            try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream("./jwks.cert"), "utf-8"))) {
                writer.write("-----BEGIN CERTIFICATE-----");
                writer.append("\n"+ cert + "\n");
                writer.append("-----END CERTIFICATE-----");
            }
            /*CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream ("./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);*/

            FileReader file = new FileReader("./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
            PemReader reader = new PemReader(file);
            X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(reader.readPemObject().getContent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(caKeySpec);




            /*final String PUBLIC_KEY_FILE_RSA = "src/test/resources/rsa-public-from-Roland.pem";
            RSAPublicKey publicKey = (RSAPublicKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");*/


            //PublicKey publicKey = cer.getPublicKey();

/*
            FileInputStream fin = new FileInputStream("/Users/jdahmubed/documents/jwksRSA.json");
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
            PublicKey publicKey = certificate.getPublicKey();*/

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
