package com.auth0.jwt.jwts;

import com.auth0.jwt.ClockImpl;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.Verification;

public class FbJWT extends JWT.BaseVerification implements Verification{

    FbJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @param userId
     * @param appId
     * @return
     */
    public Verification createVerifierForFb(String userId, String appId) {
        return withUserId(userId).withAppId(appId);
    }

    /**
     * Require a specific userId ("userId") claim.
     *
     * @param userId the required userId value
     * @return this same Verification instance.
     */
    public Verification withUserId(String userId) {
        requireClaim("userId", userId);
        return this;
    }

    /**
     * Require a specific appId ("appId") claim.
     *
     * @param appId the required appId value
     * @return this same Verification instance.
     */
    public Verification withAppId(String appId) {
        requireClaim("appId", appId);
        return this;
    }

    /**
     * Returns a {Verification} to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return Verification
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static Verification require(Algorithm algorithm) {
        return FbJWT.init(algorithm);
    }

    /**
     * Initialize a Verification instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a FbJWT instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new FbJWT(algorithm);
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
