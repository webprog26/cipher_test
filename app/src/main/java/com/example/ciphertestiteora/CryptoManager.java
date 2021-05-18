package com.example.ciphertestiteora;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoManager {

    private static final String SAMPLE_ALIAS = "MYALIAS";

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 16;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static void encrypt(final String textToEncrypt, final OnTextEncryptedListener listener) {
        final byte[] iv = getRandomNonce();

        try {
            final byte[] encrypted = encrypt(textToEncrypt.getBytes(StandardCharsets.UTF_8), getAESKeyFromPassword(SAMPLE_ALIAS.toCharArray(), iv), iv);

            listener.onSrcArrayCreated(iv);
            listener.onTextEncrypted(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void decrypt(final byte[] encrypted, final byte[] src, final OnTextDecryptedListener listener) {
       try {
           final String decrypted  = decrypt(encrypted, getAESKeyFromPassword(SAMPLE_ALIAS.toCharArray(), src), src);

           listener.onTextDecrypted(decrypted);
       } catch (Exception e) {
           e.printStackTrace();
       }
    }

    private static byte[] encrypt(final byte[] pText, final SecretKey secret, final byte[] iv) throws Exception {

        final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        return cipher.doFinal(pText);
    }

    private static String decrypt(final byte[] cText, final SecretKey secret, final byte[] iv) throws Exception {

        final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        final byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);
    }

    private static byte[] getRandomNonce() {
        final byte[] nonce = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static SecretKey getAESKeyFromPassword(final char[] password, final byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final int ITERATION_COUNT = 65536;
        final int KEY_LENGTH = 256;
        final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
        final String SECRET_KEY_SPEC_ALGORITHM = "AES";

        final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);

        final KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_SPEC_ALGORITHM);
    }
}
