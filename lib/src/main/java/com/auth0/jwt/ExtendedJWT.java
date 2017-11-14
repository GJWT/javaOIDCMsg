package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.Verification;

import java.util.Date;
import java.util.List;

public class ExtendedJWT extends GoogleJWT implements GoogleVerification{

    ExtendedJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }


    public Verification createVerifierForExtended(String picture, String email, List<String> issuer,
                                                List<String> audience, String name, long nbf, long expLeeway, long iatLeeway) {
        Verification verification = createVerifierForGoogle(picture, email, issuer, audience, name, expLeeway, iatLeeway);
        return verification.withNbf(nbf);
    }

    public static GoogleVerification require(Algorithm algorithm) {
        return ExtendedJWT.init(algorithm);
    }

    static GoogleVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new ExtendedJWT(algorithm);
    }

    /**
     * Require a specific Not Before ("nbf") claim.
     *
     * @param nbf the required Not Before value
     * @return this same Verification instance.
     */
    @Override
    public Verification withNbf(long nbf) {
        requireClaim("nbf", nbf);
        return this;
    }

}
