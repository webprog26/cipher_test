package com.example.ciphertestiteora;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public class CryptoHelper {

    private static final String SAMPLE_ALIAS = "MYALIAS";

    private Encryptor encryptor;
    private Decryptor decryptor;

    public CryptoHelper() {
        this.encryptor = new Encryptor();
        try {
            this.decryptor = new Decryptor();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException |
                IOException e) {
            e.printStackTrace();
        }
    }

    public void encrypt(final String textToEncrypt, final OnTextEncryptedListener listener) {
        try {
            listener.onTextEncrypted(encryptor.encrypt(textToEncrypt, listener));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException | IOException
                | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | SignatureException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void decrypt(final byte[] encrypted, final byte[] srcArray, final OnTextDecryptedListener listener) {
        try {
            listener.onTextDecrypted(decryptor.decrypt(encrypted, srcArray));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | KeyStoreException | NoSuchPaddingException | NoSuchProviderException
                | IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static class Decryptor {

        private static final String TRANSFORMATION = "AES/GCM/NoPadding";
        private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

        private KeyStore keyStore;

        Decryptor() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
            initKeyStore();
        }

        private void initKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
            this.keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        }

        String decrypt(final byte[] encryptedData, final byte[] encryptionIv) throws
                UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
                NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
                IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec);

            return new String(cipher.doFinal(encryptedData), StandardCharsets.UTF_8);
        }

        private SecretKey getSecretKey() throws NoSuchAlgorithmException,
                UnrecoverableEntryException, KeyStoreException {
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(CryptoHelper.SAMPLE_ALIAS, null)).getSecretKey();
        }
    }

    private static class Encryptor {

        private static final String TRANSFORMATION = "AES/GCM/NoPadding";
        private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

        byte[] encrypt(final String textToEncrypt, final OnTextEncryptedListener listener)
                throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
                NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
                InvalidAlgorithmParameterException, SignatureException, BadPaddingException,
                IllegalBlockSizeException {

            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
            Log.i("ciph_deb", "secret key is null: " + (getSecretKey().getEncoded() == null));

            listener.onSrcArrayCreated(cipher.getIV());

            return cipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8));
        }


        @NonNull
        private SecretKey getSecretKey() throws NoSuchAlgorithmException,
                NoSuchProviderException, InvalidAlgorithmParameterException {

            final KeyGenerator keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

            keyGenerator.init(new KeyGenParameterSpec.Builder(CryptoHelper.SAMPLE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
            return keyGenerator.generateKey();
        }
    }

    public static class CryptoUtils {

        public static String fromBytesArray(final byte[] bytes) {
            return Base64.encodeToString(bytes, Base64.DEFAULT);
        }

        public static byte[] fromString(final String source) {
            return Base64.decode(source, Base64.DEFAULT);
        }
    }
}
