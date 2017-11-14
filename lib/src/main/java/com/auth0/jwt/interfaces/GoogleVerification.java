package com.auth0.jwt.interfaces;

import java.util.Date;
import java.util.List;

public interface GoogleVerification extends Verification{

    Verification createVerifierForGoogle(String picture, String email, List<String> issuer,
                                         List<String> audience, String name, long expLeeway, long iatLeeway);

    Verification withPicture(String picture);

    Verification withEmail(String email);

    GoogleVerification withName(String name);

     Verification createVerifierForExtended(String picture, String email, List<String> issuer,
                                           List<String> audience, String name, long nbf, long expLeeway, long iatLeeway);

}
