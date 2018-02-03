package com.auth0.jwt.oiccli.Utils;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.tuples.Tuple;
import com.auth0.jwt.oiccli.exceptions.MissingRequiredAttribute;
import com.google.common.base.Strings;
import java.io.File;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

public class Utils {

    public static Message requestObjectEncryption(Message message, ClientInfo clientInfo, Map<String,Object> args) throws MissingRequiredAttribute {
        String encryptionAlg = (String) args.get("requestObjectEncryptionAlg");

        if(Strings.isNullOrEmpty(encryptionAlg)) {
            List<String> listOfAlgs = clientInfo.getBehavior().get("requestObjectEncryptionAlg");
            if(listOfAlgs != null || !listOfAlgs.isEmpty()) {
                encryptionAlg = listOfAlgs.get(0);
            }

            if(encryptionAlg == null) {
                return message;
            }
        }

        String encryptionEnc = (String) args.get("requestObjectEncryptionEnc");

        if(Strings.isNullOrEmpty(encryptionEnc)) {
            List<String> listOfAlgs = clientInfo.getBehavior().get("requestObjectEncryptionEnc");
            if(listOfAlgs != null || !listOfAlgs.isEmpty()) {
                encryptionEnc = listOfAlgs.get(0);
            }

            if(encryptionEnc == null) {
                throw new MissingRequiredAttribute("No requestObjectEncryptionEnc specified");
            }
        }

        JWE jwe = new JWE(message, encryptionAlg, encryptionEnc);
        String keyType = StringUtil.alg2keytype(encryptionAlg);

        String kid = (String) args.get("encKid");
        if(Strings.isNullOrEmpty(kid)) {
            kid = "";
        }

        if(!args.containsKey("target")) {
            throw new MissingRequiredAttribute("No target specified");
        }

        List<Key> keys;
        if(!Strings.isNullOrEmpty(kid)) {
            keys = clientInfo.getKeyJar().getEncryptKey(keyType, args.get("target"), kid);
            jwe.setKid(kid);
        } else {
            keys = clientInfo.getKeyJar().getEncryptKey(keyType, args.get("target"));
        }

        return jwe.encrypt(keys);
    }

    public static Tuple constructRequestUri(String localDir, String basePath, Map<String,String> args) {
        File file = new File(localDir);
        if(!file.isDirectory()) {
            file.mkdirs();
        }
        String name = StringUtil.generateRandomString(10) + ".jwt";
        File fileExists = Paths.get(localDir, name).toFile();
        while(fileExists.exists()) {
            name = StringUtil.generateRandomString(10);
            fileExists = Paths.get(localDir, name).toFile();
        }

        String webName = basePath + name;
        return new Tuple(fileExists.toString(), webName);
    }
}
