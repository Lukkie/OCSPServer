import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * Created by Gilles Callebaut on 23/02/2016.
 */
public class Crypto {
    public static final String DIGEST_ALGORITHM = "SHA-256";
    public static final String SIGN_ALGORITHM = "SHA256withRSA";
    public static final String ASYMMETRIC_ALGORITHM = "RSA";
    //public static final String SYMMETRIC_ALGORITHM = "AES/CBC/PKCS5Padding";
    //public static final String SYMMETRIC_ALGORITHM = "AES/CBC/NoPadding";
    public static final String SYMMETRIC_ALGORITHM = "AES/CBC/NoPadding";




    /**************************** GENERATING KEYS *******************************/


    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
            keyGen.initialize(1024);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static SecretKey generateSymmetricKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**************************** ENCRYPTION / DECRYPTION *******************************/

    public static byte[] encrypt(byte[] encryptMe, Key key, Cipher c) {
        try {
            byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec spec = new IvParameterSpec(ivdata);

            //System.out.print("Before encrypting: ");
            //Tools.printByteArray(encryptMe);

            c.init(ENCRYPT_MODE, key, spec);
            byte[] results = c.doFinal(encryptMe);

            //System.out.print("After encrypting: ");
            //Tools.printByteArray(results);

            return results;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptWithAES(byte[] data, SecretKey key) {
        try {
            Cipher cipherAes = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipherAes.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipherAes.doFinal(data);
            return encryptedBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] decryptMe, Key key, Cipher c) {
        try {
            byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec spec = new IvParameterSpec(ivdata);

            byte[] d = decryptMe;
            //System.out.print("Before decrypting: ");
            //Tools.printByteArray(d);

            c.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] results = c.doFinal(d);

            //System.out.print("After decrypting: ");
            //Tools.printByteArray(results);

            return results;
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }



    /**************************** SIGNATURE / DIGEST *******************************/

    public static byte[] digest(String content) {
        MessageDigest md;
        byte[] digest;
        try {
            md = MessageDigest.getInstance(DIGEST_ALGORITHM);
            md.update(content.getBytes());
            digest = md.digest();
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getLocalizedMessage());
            return null;
        }
        return digest;
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        Signature signer;
        try {
            signer = Signature.getInstance(SIGN_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(data);
            return (signer.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static boolean verify(byte[] data, PublicKey publicKey, byte[] sign) {
        Signature signer;
        try {
            signer = Signature.getInstance(SIGN_ALGORITHM);
            signer.initVerify(publicKey);
            signer.update(data);
            return (signer.verify(sign));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] encryptWithPublicKeyRSA(byte[] data, PublicKey pk) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Data to encrypt: ");

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

        asymCipher.init(Cipher.ENCRYPT_MODE, pk);

        byte[] encryptedData = asymCipher.doFinal(data);

        return encryptedData;
    }
}
