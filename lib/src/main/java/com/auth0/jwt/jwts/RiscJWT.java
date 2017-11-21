package com.auth0.jwt.jwts;

import com.auth0.jwt.ClockImpl;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.Verification;

import java.util.List;

public class RiscJWT extends JWT.BaseVerification implements Verification {

    RiscJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @param jti
     * @param issuer
     * @param audience
     * @param iatLeeway
     * @param expLeeway
     * @return
     */
    public Verification createVerifierForRisc(String jti, List<String> issuer,
                                              List<String> audience, long iatLeeway, long expLeeway, long nbf) {
        Verification verification = withJWTId(jti).withIssuer(issuer.toArray(new String[issuer.size()])).acceptIssuedAt(iatLeeway);

        if(audience != null && !audience.isEmpty()) {
            verification.withAudience(audience.toArray(new String[audience.size()]));
        }

        if(nbf >= 0) {
            verification.acceptNotBefore(iatLeeway);
        }

        if(expLeeway >= 0) {
            verification.acceptExpiresAt(expLeeway);
        }

        return verification;
    }

    /**
     * Returns a {Verification} to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return Verification
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static Verification require(Algorithm algorithm) {
        return RiscJWT.init(algorithm);
    }

    /**
     * Initialize a Verification instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a RiscJWT instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new RiscJWT(algorithm);
    }

    /**
     * Creates a new and reusable instance of the JWT with the configuration already provided.
     *
     * @return a new JWT instance.
     */
    @Override
    public JWT build() {
        return this.build(new ClockImpl());
    }

    /**
     * Creates a new and reusable instance of the JWT the configuration already provided.
     * ONLY FOR TEST PURPOSES.
     *
     * @param clock the instance that will handle the current time.
     * @return a new JWT instance with a custom Clock.
     */
    public JWT build(Clock clock) {
        addLeewayToDateClaims();
        return new JWT(algorithm, claims, clock);
    }
}
