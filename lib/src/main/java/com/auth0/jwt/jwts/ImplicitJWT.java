package com.auth0.jwt.jwts;

import com.auth0.jwt.ClockImpl;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.Verification;

import java.util.List;

public class ImplicitJWT extends JWT.BaseVerification implements Verification{

    ImplicitJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @issuer scope
     * @param issuer
     * @param audience
     * @return
     */
    public Verification createVerifierForImplicit(List<String> issuer,
                                                List<String> audience, long iatLeeway) {
        return withIssuer(issuer.toArray(new String[issuer.size()])).withAudience(audience.toArray(new String[audience.size()]))
                .acceptIssuedAt(iatLeeway);
    }

    /**
     * Returns a {Verification} to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return Verification
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static Verification require(Algorithm algorithm) {
        return ImplicitJWT.init(algorithm);
    }

    /**
     * Initialize a Verification instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a ImplicitJWT instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new ImplicitJWT(algorithm);
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
