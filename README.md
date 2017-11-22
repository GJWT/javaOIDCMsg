

# Java JWT

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/java-jwt.svg?style=flat-square)](https://circleci.com/gh/auth0/java-jwt/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/java-jwt/v3.svg?style=flat-square)](https://codecov.io/github/auth0/java-jwt)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)

A Java implementation of [JSON Web Tokens (draft-ietf-oauth-json-web-token-08)](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

If you're looking for an **Android** version of the JWT Decoder take a look at our [JWTDecode.Android](https://github.com/auth0/JWTDecode.Android) library.

## Installation

### Maven

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.3.0</version>
</dependency>
```

### Gradle

```gradle
compile 'com.auth0:java-jwt:3.3.0'
```

## Available Algorithms

The library implements JWT Verification and Signing using the following algorithms:

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS384 | HMAC384 | HMAC with SHA-384 |
| HS512 | HMAC512 | HMAC with SHA-512 |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | RSA384 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | RSA512 | RSASSA-PKCS1-v1_5 with SHA-512 |
| ES256 | ECDSA256 | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384 | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512 | ECDSA with curve P-521 and SHA-512 |

## Supported token profile types

#### Basic Token

- Standard claims: *iss, sub, iat, jti*
- Nonstandard claims: *aud, exp, nbf*

#### Extended Token
- Standard claims: *name, email, picture, iss, sub, iat*
- Nonstandard claims: *aud, exp, nbf*

#### Access Token
- Standard claims: *iss, sub, iat*
- Nonstandard claims: *aud, exp*

#### Facebook Token
- Standard claims: *user_id, app_id, issued_at*
- Nonstandard claims: *expired_at*

#### Google Token
- Standard claims: *name, email, picture, iss, sub, iat*
- Nonstandard claims: *exp, aud*

#### Implicit Access Token
- Standard claims: *iss, sub, iat*
- Nonstandard claims: *aud*

#### Refresh Token
- Standard claims: *refresh_token, access_token*

#### Risc Token
- Standard claims: *jti, iss, sub, iat*
- Nonstandard claims: *aud, nbf, exp*

#### Scoped Access Token
- Standard claims: *iss, sub, iat, scope*
- Nonstandard claims: *aud, exp*

### Pick the Algorithm

The Algorithm defines how a token is signed and verified. It can be instantiated with the raw value of the secret in the case of HMAC algorithms, or the key pairs or `KeyProvider` in the case of RSA and ECDSA algorithms. Once created, the instance is reusable for token signing and verification operations.

When using RSA or ECDSA algorithms and you just need to **sign** JWTs you can avoid specifying a Public Key by passing a `null` value. The same can be done with the Private Key when you just need to **verify** JWTs.


#### Using static secrets or keys:

```java
//HMAC
Algorithm algorithmHS = Algorithm.HMAC256("secret");

//RSA
RSAPublicKey publicKey = //Get the key instance
RSAPrivateKey privateKey = //Get the key instance
Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
```

#### Using a KeyProvider:

By using a `KeyProvider` you can change in runtime the key used either to verify the token signature or to sign a new token for RSA or ECDSA algorithms. This is achieved by implementing either `RSAKeyProvider` or `ECDSAKeyProvider` methods:

- `getPublicKeyById(String kid)`: Its called during token signature verification and it should return the key used to verify the token. If key rotation is being used, e.g. [JWK](https://tools.ietf.org/html/rfc7517) it can fetch the correct rotation key using the id. (Or just return the same key all the time).
- `getPrivateKey()`: Its called during token signing and it should return the key that will be used to sign the JWT.
- `getPrivateKeyId()`: Its called during token signing and it should return the id of the key that identifies the one returned by `getPrivateKey()`. This value is preferred over the one set in the `JWTCreator.Builder#withKeyId(String)` method. If you don't need to set a `kid` value avoid instantiating an Algorithm using a `KeyProvider`.


The following snippet uses example classes showing how this would work:


```java
final JwkStore jwkStore = new JwkStore("{JWKS_FILE_HOST}");
final RSAPrivateKey privateKey = //Get the key instance
final String privateKeyId = //Create an Id for the above key

RSAKeyProvider keyProvider = new RSAKeyProvider() {
    @Override
    public RSAPublicKey getPublicKeyById(String kid) {
        //Received 'kid' value might be null if it wasn't defined in the Token's header
        RSAPublicKey publicKey = jwkStore.get(kid);
        return (RSAPublicKey) publicKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public String getPrivateKeyId() {
        return privateKeyId;
    }
};

Algorithm algorithm = Algorithm.RSA256(keyProvider);
//Use the Algorithm to create and verify JWTs.
```

> For simple key rotation using JWKs try the [jwks-rsa-java](https://github.com/auth0/jwks-rsa-java) library.


### Create and Sign a Token

You'll first need to create a `JWTCreator` instance by calling `JWT.create()`. Use the builder to define the custom Claims your token needs to have. Finally to get the String token call `sign()` and pass the `Algorithm` instance.

* Example using `HS256`

```java
try {
    Algorithm algorithm = Algorithm.HMAC256("secret");
    String token = JWT.create()
        .withIssuer("auth0")
        .sign(algorithm);
} catch (UnsupportedEncodingException exception){
    //UTF-8 encoding not supported
} catch (JWTCreationException exception){
    //Invalid Signing configuration / Couldn't convert Claims.
}
```

* Example using `RS256`

```java
RSAPublicKey publicKey = //Get the key instance
RSAPrivateKey privateKey = //Get the key instance
try {
    Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
    String token = JWT.create()
        .withIssuer("auth0")
        .sign(algorithm);
} catch (JWTCreationException exception){
    //Invalid Signing configuration / Couldn't convert Claims.
}
```

If a Claim couldn't be converted to JSON or the Key used in the signing process was invalid a `JWTCreationException` will raise.


### Verify a Token

You'll first need to create a `Verification` instance by calling `JWT.require()` and passing the `Algorithm` instance. Once you have the `Verification` instance, you can call the corresponding verifier method.  For the example of Google,
you would have a `GoogleVerificiation` instance that has inherited from the `Verification` instance in order to call `createVerifierForGoogle()`, and you would pass in the claims that you would want to be verified.
Once you call `build`, you would get back a `JWT` object and with that, you would call `decode()` while passing in the token that was created after signing.  You will get back a `DecodedJWT` object, which contains all of the claims, and you can verify
those claims against what's the expected claims by calling `verifyClaims()`.

* Example using `HS256`

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
Algorithm algorithm = Algorithm.HMAC256("secret");
GoogleVerification verification = GoogleJWT.require(algorithm);
JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
       NAME, 1, 1).build();
DecodedJWT jwt = verifier.decode(token);
Map<String, Claim> claims = jwt.getClaims();
verifyClaims(claims, exp);
```

* Example using `RS256`

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
RSAPublicKey publicKey = //Get the key instance
RSAPrivateKey privateKey = //Get the key instance

Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
GoogleVerification verification = GoogleJWT.require(algorithm);
JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
    NAME, 1, 1).build();
DecodedJWT jwt = verifier.decode(token);
Map<String, Claim> claims = jwt.getClaims();
verifyClaims(claims, exp);
```

If the token has a Claim requirement that has not been met, an `InvalidClaimException` will raise.
If the token has an invalid signature, an `AlgorithmMismatchException` will raise.

#### Time Validation

The JWT token may include DateNumber fields that can be used to validate that:
* The token was issued in a past date `"iat" < TODAY`
* The token hasn't expired yet `"exp" > TODAY` and
* The token can already be used. `"nbf" > TODAY`

When verifying a token the time validation occurs automatically, resulting in a `JWTVerificationException` being throw when the values are invalid. If any of the previous fields are missing they won't be considered in this validation.

To specify a **nbf value** in which the Token should still be considered valid, use the `withNbf()` method in the respective `Creator` builder and pass a Date object. This applies to every item listed above.
**NOTE:**  `Nbf` and `iat` date values should be in the past, but the `exp` value should be in the future.
```java
Verification verifier = JWT.require(algorithm)
    .withNbf(new Date(2016,1,1))
    .build();
```

You can also specify a custom value for a given Date claim and override the default one for only that claim.

```java
Verification verifier = JWT.require(algorithm)
    .withNbf(new Date(2016,1,1))
    .withExp(new Date(2100,1,1))
    .build();
```

If you need to test this behaviour in your lib/app cast the `Verification` instance to a `BaseVerification` to gain visibility of the `verification.build()` method that accepts a custom `Clock`. e.g.:

```java
BaseVerification verification = (BaseVerification) JWT.require(algorithm)
    .acceptLeeway(1)
    .acceptExpiresAt(5);
Clock clock = new CustomClock(); //Must implement Clock interface
JWT verifier = verification.build(clock);
```

### Decode a Token

This example is for an Implicit JWT token and can be applied to all the types of tokens:
```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOlsic3ViamVjdCJdLCJpc3MiOlsiYWNjb3VudHMuZmFrZS5jb20iXSwiYXVkIjoiYXVkaWVuY2UiLCJpYXQiOi0xMjQ1MjgxNTI3fQ.-eRoMolUy7PnEcpvfs-jTEvP6qagBZ1G_lqp1jY3Nqg";
Verification verification = ImplicitJWT.require(algorithm);
JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience"), 1).build();
DecodedJWT jwt = verifier.decode(token);
```

If the token has an invalid syntax or the header or payload are not JSONs, a `JWTDecodeException` will raise.


### Header Claims

#### Algorithm ("alg")

Returns the Algorithm value or null if it's not defined in the Header.

```java
String algorithm = jwt.getAlgorithm();
```

#### Type ("typ")

Returns the Type value or null if it's not defined in the Header.

```java
String type = jwt.getType();
```

#### Content Type ("cty")

Returns the Content Type value or null if it's not defined in the Header.

```java
String contentType = jwt.getContentType();
```

#### Key Id ("kid")

Returns the Key Id value or null if it's not defined in the Header.

```java
String keyId = jwt.getKeyId();
```

#### Private Claims

Additional Claims defined in the token's Header can be obtained by calling `getHeaderClaim()` and passing the Claim name. A Claim will always be returned, even if it can't be found. You can check if a Claim's value is null by calling `claim.isNull()`.

```java
Claim claim = jwt.getHeaderClaim("owner");
```

When creating a Token with the `JWTCreator.init()` you can specify header Claims by calling `withHeader()` and passing both the map of claims.

```java
Map<String, Object> headerClaims = new HashMap();
headerClaims.put("owner", "auth0");
String token = JWTCreator.init()
        .withHeader(headerClaims)
        .sign(algorithm);
```

> The `alg` and `typ` values will always be included in the Header after the signing process.


### Payload Claims

#### Issuer ("iss")

Returns the Issuer value or null if it's not defined in the Payload.

```java
String issuer = jwt.getIssuer();
```

#### Subject ("sub")

Returns the Subject value or null if it's not defined in the Payload.

```java
String subject = jwt.getSubject();
```

#### Audience ("aud")

Returns the Audience value or null if it's not defined in the Payload.

```java
List<String> audience = jwt.getAudience();
```

#### Expiration Time ("exp")

Returns the Expiration Time value or null if it's not defined in the Payload.

```java
Date expiresAt = jwt.getExpiresAt();
```

#### Not Before ("nbf")

Returns the Not Before value or null if it's not defined in the Payload.

```java
Date notBefore = jwt.getNotBefore();
```

#### Issued At ("iat")

Returns the Issued At value or null if it's not defined in the Payload.

```java
Date issuedAt = jwt.getIssuedAt();
```

#### JWT ID ("jti")

Returns the JWT ID value or null if it's not defined in the Payload.

```java
String id = jwt.getId();
```

#### Nonstandard Claims

Nonstandard Claims defined in the token's Payload can be obtained by calling `getClaims()` or `getClaim()` and passing the Claim name. A Claim will always be returned, even if it can't be found. You can check if a Claim's value is null by calling `claim.isNull()`.

```java
Map<String, Claim> claims = jwt.getClaims();    //Key is the Claim name
Claim claim = claims.get("isAdmin");
```

or

```java
Claim claim = jwt.getClaim("isAdmin");
```

When creating an Implicit Token for example with the `ImplicitJwtCreator.build()` you can specify a custom Claim by calling `withNonStandardClaim()` and passing both the name and the value.

```java
String token = ImplicitJwtCreator.build()
        .withNonStandardClaim("nonStandardClaim", 123)
        .withArrayClaim("array", new Integer[]{1, 2, 3})
        .sign(algorithm);
```

**NOTE:** Nonstandard claims do not need to verified.

> Currently supported classes for custom JWT Claim creation and verification are: Boolean, Integer, Double, String, Date and Arrays of type String and Integer.


### Claim Class
The Claim class is a wrapper for the Claim values. It allows you to get the Claim as different class types. The available helpers are:

#### Primitives
* **asBoolean()**: Returns the Boolean value or null if it can't be converted.
* **asInt()**: Returns the Integer value or null if it can't be converted.
* **asDouble()**: Returns the Double value or null if it can't be converted.
* **asLong()**: Returns the Long value or null if it can't be converted.
* **asString()**: Returns the String value or null if it can't be converted.
* **asDate()**: Returns the Date value or null if it can't be converted. This must be a NumericDate (Unix Epoch/Timestamp). Note that the [JWT Standard](https://tools.ietf.org/html/rfc7519#section-2) specified that all the *NumericDate* values must be in seconds.

#### Custom Classes and Collections
To obtain a Claim as a Collection you'll need to provide the **Class Type** of the contents to convert from.

* **as(class)**: Returns the value parsed as **Class Type**. For collections you should use the `asArray` and `asList` methods.
* **asMap()**: Returns the value parsed as **Map<String, Object>**.
* **asArray(class)**: Returns the value parsed as an Array of elements of type **Class Type**, or null if the value isn't a JSON Array.
* **asList(class)**: Returns the value parsed as a List of elements of type **Class Type**, or null if the value isn't a JSON Array.

If the values can't be converted to the given **Class Type** a `JWTDecodeException` will raise.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker.

## Author

Justin Dahmubed\
Application Engineer II @ Google

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
