package chiffrementclient;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@SuppressWarnings("unused")
public class CryptoUtils {

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return cipher.doFinal(data);
    }

    public static byte[] aesEncrypt(byte[] plain, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(plain);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(iv);
        out.write(cipherText);
        return out.toByteArray();
    }

    public static byte[] aesDecrypt(byte[] ivAndCipher, SecretKey key) throws Exception {
        if (ivAndCipher.length < 16) throw new IllegalArgumentException("Données trop courtes");
        byte[] iv = Arrays.copyOfRange(ivAndCipher, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(ivAndCipher, 16, ivAndCipher.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public static SecretKey rebuildAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    public static PublicKey rebuildRSAPublicKey(byte[] pubBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static String toBase64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

	public static PublicKey publicKeyFromBase64(String pubB64) {

		return null;
	}

	public static byte[] fromB64(String string) {

		return null;
	}
}