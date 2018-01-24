package oiccli.service;

import java.util.HashMap;
import java.util.Map;

public class Service {

    public static final Map<String, String> PREFERENCE2PROVIDER =
            new HashMap<String, String>() {{
                put("request_object_signing_alg", "request_object_signing_alg_values_supported");
                put("request_object_encryption_alg", "request_object_encryption_alg_values_supported");
                put("request_object_encryption_enc", "request_object_encryption_enc_values_supported");
                put("userinfo_signed_response_alg", "userinfo_signing_alg_values_supported");
                put("userinfo_encrypted_response_alg", "userinfo_encryption_alg_values_supported");
                put("userinfo_encrypted_response_enc", "userinfo_encryption_enc_values_supported");
                put("id_token_signed_response_alg", "id_token_signing_alg_values_supported");
                put("id_token_encrypted_response_alg", "id_token_encryption_alg_values_supported");
                put("id_token_encrypted_response_enc", "id_token_encryption_enc_values_supported");
                put("default_acr_values", "acr_values_supported");
                put("subject_type", "subject_types_supported");
                put("token_endpoint_auth_method", "token_endpoint_auth_methods_supported");
                put("token_endpoint_auth_signing_alg", "token_endpoint_auth_signing_alg_values_supported");
                put("response_types", "response_types_supported");
                put("grant_types", "grant_types_supported");
            }};

    public static final Map<String, String> PROVIDERDEFAULT =
            new HashMap<String, String>() {{
                put("token_endpoint_auth_method", "client_secret_basic");
                put("id_token_signed_response_alg", "RS256");
            }};


    public Service(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
    }
}
