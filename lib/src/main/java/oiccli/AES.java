package oiccli;

import org.junit.Assert;
import org.bouncycastle.util.encoders.Base64;
import oiccli.exceptions.AESError;

import java.util.Arrays;
import java.util.List;

public class AES {

    private static final int BLOCK_SIZE = 16;
    private byte[] key;
    private int mode;
    private byte[] iv;
    private AES kernel;

    public AES(byte[] key, byte[] iv, int mode) {
        assert key instanceof byte[];
        assert iv instanceof byte[];
        this.key = key;
        this.mode = mode;
        this.iv = iv;
        this.kernel = new AES(this.key, this.mode, this.iv);
    }

    public static List<Object> buildCipher(byte[] key, byte[] iv, String alg)
            throws AESError {
        String[] algArr = alg.split("_");

        if (iv == null) {

        } else {
            Assert.assertTrue(key.length == 16); //AES.blockSize
        }

        int bits = Integer.parseInt(algArr[1]);
        if (bits != 128 && bits != 192 && bits != 256) {
            throw new AESError("Unsupported key length");
        }

        try {
            Assert.assertTrue(key.length == bits >> 3);
        } catch (AssertionError error) {
            throw new AESError("Wrong key length");
        }

        /*
        CONVERT THIS TO JAVA

        try:
        return AES.new(tobytes(key), POSTFIX_MODE[cmode], tobytes(iv)), iv
        except KeyError:
        raise AESError("Unsupported chaining mode")*/
    }

    public static List<Object> buildCipher(byte[] key, byte[] iv) throws AESError {
        buildCipher(key, iv, "aes_128_cbc");
        return null;
    }

    public static void encrypt(byte[] key, String msg, byte[] iv, String alg, String padding,
                               boolean shouldBase64Encrypt, int blockSize) {

        int blockSizeLocal;
        if (padding.equals("PKCS#7")) {
            blockSizeLocal = blockSize;
        } else if (padding.equals("PKCS#5")) {
            blockSizeLocal = 8;
        } else {
            blockSizeLocal = 0;
        }

        if (blockSizeLocal != 0) {
            int pLength = blockSizeLocal - (msg.length() % blockSizeLocal);
            char character = (char) pLength;
            msg += (character * pLength);
        }

        try {
            List<Object> buildCipher = buildCipher(key, iv, alg);
        } catch (AESError aesError) {
            aesError.printStackTrace();
        }

        if (shouldBase64Encrypt) {
            Base64.encode(cmsg);
        } else {
            return cmsg;
        }
    }

    public static void encrypt(byte[] key, String msg) {
        return encrypt(key, msg, null, "aes_128_cbc", "PKCS#7", true, BLOCK_SIZE);
    }

    public static byte[] decrypt(byte[] key, String msg, byte[] iv, String padding, boolean shouldBase64Decrypt) throws AESError {
        byte[] data;
        if (shouldBase64Decrypt) {
            data = Base64.decode(msg);
        } else {
            data = msg.getBytes();
        }

        byte[] ivByteArr = Arrays.copyOfRange(data, 0, 16);
        if (iv != null) {
            Assert.assertEquals(iv, ivByteArr);
        }
        List<Object> cipherList = buildCipher(key, iv);
        //insert python code
        byte[] decrpytArr = cipher.decrypt(data);
        byte[] res = Arrays.copyOfRange(decrpytArr, 16, decrpytArr.length);

        if (padding.equals("PKCS#5") || padding.equals("PKCS#7")) {
            res = Arrays.copyOfRange(res, 0, res[res.length - 1]);
        }

        return Base64.decode(res);
    }

    public static void decrypt(byte[] key, String msg, byte[] iv) {
        return decrypt(key, msg, null, "PKCS#7", true);
    }

    public void addAssociatedData(String data) {
        data = new String(Base64.encode(data.getBytes()));
        this.kernel.update(data);
    }

    public List<Object> encryptAndTag(byte[] clearData) {
        return this.kernel.encryptAndDigest(clearData);
    }

    public void decryptAndVerify(byte[] cypherData, byte[] tag) {
        return this.kernel.decryptAndVerify(cypherData, tag);
    }
}
