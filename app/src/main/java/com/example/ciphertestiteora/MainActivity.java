package com.example.ciphertestiteora;

import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "ciph_deb";

    private static final String KEY_ENCRYPTED_TEXT = "encrypted_text";
    private static final String KEY_SRC_ARRAY = "src_array";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

        final String dataString = "[{\"id\":\"786f03bd-3fd3-45e0-8ed2-4ba3d127e005\",\"timestamp\":1621323584115,\"target_url\":\"https:\\/\\/en.m.wikipedia.org\\/\",\"referrer_url\":\"null\"},{\"id\":\"786f03bd-3fd3-45e0-8ed2-4ba3d127e005\",\"timestamp\":1621323589679,\"target_url\":\"https:\\/\\/en.m.wikipedia.org\\/wiki\\/Portal:Geography\",\"referrer_url\":\"https:\\/\\/en.m.wikipedia.org\\/wiki\\/Main_Page\"}]";

        final CryptoHelper iteoraCryptoHelper = new CryptoHelper();

        ((Button) findViewById(R.id.btn_encrypt)).setOnClickListener((v) -> {
            Log.i(TAG, "btn encrypt clicked");
//            iteoraCryptoHelper.encrypt(dataString, new OnTextEncryptedListener() {
//                @Override
//                public void onTextEncrypted(byte[] encrypted) {
//                    final String encryptedText = CryptoHelper.CryptoUtils.fromBytesArray(encrypted);
//                    Log.i(TAG, "encryptedText: " + encryptedText);
//
//                    preferences.edit().putString(KEY_ENCRYPTED_TEXT, encryptedText).apply();
//                }
//
//                @Override
//                public void onSrcArrayCreated(byte[] srcArray) {
//                    preferences.edit().putString(KEY_SRC_ARRAY, CryptoHelper.CryptoUtils.fromBytesArray(srcArray)).apply();
//                }
//            });


            CryptoManager.encrypt(dataString, new OnTextEncryptedListener() {
                @Override
                public void onTextEncrypted(byte[] encrypted) {
                    final String encryptedText = CryptoHelper.CryptoUtils.fromBytesArray(encrypted);
                    Log.i("ciph_deb", "text encrypted: " + encryptedText);
                    preferences.edit().putString(KEY_ENCRYPTED_TEXT, encryptedText).apply();
                }

                @Override
                public void onSrcArrayCreated(byte[] srcArray) {
                    final String srcArrayText = CryptoHelper.CryptoUtils.fromBytesArray(srcArray);
                    Log.i("ciph_deb", "text srcArray: " + srcArrayText);
                    preferences.edit().putString(KEY_SRC_ARRAY, srcArrayText).apply();
                }
            });
        });

        ((Button) findViewById(R.id.btn_decrypt)).setOnClickListener((v) -> {
            Log.i(TAG, "btn decrypt clicked");
//            final String encryptedText = preferences.getString(KEY_ENCRYPTED_TEXT, null);
//            final String src = preferences.getString(KEY_SRC_ARRAY, null);
//            if (encryptedText != null && src != null) {
//                Log.i(TAG, "saved encrypted text: " + encryptedText);
//
//                final byte[] encrypted = CryptoHelper.CryptoUtils.fromString(encryptedText);
//                final byte[] srcArray = CryptoHelper.CryptoUtils.fromString(src);
//
//                iteoraCryptoHelper.decrypt(encrypted,  srcArray, (decryptedText) -> {
//                    Log.i(TAG, "decrypted text: " + decryptedText);
//                });
//            } else {
//                Log.i(TAG, "saved encrypted text is null");
//            }
            final String encryptedText = preferences.getString(KEY_ENCRYPTED_TEXT, null);
            final String src = preferences.getString(KEY_SRC_ARRAY, null);
            if (encryptedText != null && src != null) {
                final byte[] encrypted = CryptoHelper.CryptoUtils.fromString(encryptedText);
                final byte[] srcArray = CryptoHelper.CryptoUtils.fromString(src);

                CryptoManager.decrypt(encrypted, srcArray, decryptedText -> {
                    Log.i(TAG, "decrypted text: " + decryptedText);
                });
            }
        });
    }
}