package com.example.ciphertestiteora;

public interface OnTextEncryptedListener {

    void onTextEncrypted(final byte[] encrypted);

    void onSrcArrayCreated(final byte[] srcArray);
}
