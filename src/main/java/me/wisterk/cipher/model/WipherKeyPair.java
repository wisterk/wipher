package me.wisterk.cipher.model;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Wrapper around an X25519 key pair used for Diffie-Hellman key agreement.
 *
 * @param publicKey  the public key (safe to share)
 * @param privateKey the private key (never leaves the device)
 */
public record WipherKeyPair(PublicKey publicKey, PrivateKey privateKey) {

    public WipherKeyPair(KeyPair javaKeyPair) {
        this(javaKeyPair.getPublic(), javaKeyPair.getPrivate());
    }

    /** Public key bytes for transmission. */
    public byte[] publicKeyBytes() {
        return publicKey.getEncoded();
    }

    /** Public key as Base64 string. */
    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKeyBytes());
    }

    /** Export public key as a shareable WipherPublicKey. */
    public WipherPublicKey toPublicKey() {
        return new WipherPublicKey(publicKeyBytes());
    }
}
