package me.wisterk.cipher.stream;

import me.wisterk.cipher.crypto.AesGcmCipher;
import me.wisterk.cipher.model.EncryptedPayload;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * Decrypting stream wrapper — reads encrypted chunked input, outputs plaintext.
 *
 * Expects data in the format produced by {@link WipherEncryptingStream}:
 * <pre>
 * [4 bytes: plaintext length] [12 bytes: nonce] [N+16 bytes: ciphertext + tag]
 * ...
 * [4 bytes: 0x00000000] — end-of-stream
 * </pre>
 *
 * Each chunk is independently verified (GCM auth tag). If any chunk
 * was tampered with, an exception is thrown immediately.
 *
 * <pre>{@code
 * InputStream decrypted = WipherDecryptingStream.wrap(key, encryptedStream);
 * byte[] plaintext = decrypted.readAllBytes(); // or read chunk by chunk
 * }</pre>
 */
public final class WipherDecryptingStream extends InputStream {

    private static final int GCM_TAG_BYTES = 16;
    private static final int NONCE_BYTES = 12;

    private final byte[] key;
    private final InputStream source;

    private byte[] currentChunk;
    private int chunkPos;
    private boolean eof;

    private WipherDecryptingStream(byte[] key, InputStream source) {
        this.key = key;
        this.source = source;
        this.currentChunk = null;
        this.chunkPos = 0;
        this.eof = false;
    }

    /**
     * Wrap an encrypted InputStream into a decrypting InputStream.
     *
     * @param key    32-byte AES key (same as used for encryption)
     * @param source encrypted chunked input
     * @return InputStream producing plaintext
     */
    public static WipherDecryptingStream wrap(byte[] key, InputStream source) {
        return new WipherDecryptingStream(key, source);
    }

    @Override
    public int read() throws IOException {
        if (eof) return -1;

        if (currentChunk == null || chunkPos >= currentChunk.length) {
            if (!loadNextChunk()) return -1;
        }

        return currentChunk[chunkPos++] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (eof) return -1;

        int totalRead = 0;

        while (totalRead < len) {
            if (currentChunk == null || chunkPos >= currentChunk.length) {
                if (!loadNextChunk()) {
                    return totalRead > 0 ? totalRead : -1;
                }
            }

            int available = currentChunk.length - chunkPos;
            int toRead = Math.min(available, len - totalRead);
            System.arraycopy(currentChunk, chunkPos, b, off + totalRead, toRead);
            chunkPos += toRead;
            totalRead += toRead;
        }

        return totalRead;
    }

    @Override
    public void close() throws IOException {
        source.close();
    }

    private boolean loadNextChunk() throws IOException {
        // Read plaintext length (4 bytes)
        var lenBytes = source.readNBytes(4);
        if (lenBytes.length < 4) {
            eof = true;
            return false;
        }

        int plaintextLen = ByteBuffer.wrap(lenBytes).getInt();
        if (plaintextLen == 0) {
            eof = true;
            return false;
        }

        // Read nonce (12 bytes)
        var nonce = source.readNBytes(NONCE_BYTES);
        if (nonce.length < NONCE_BYTES) {
            throw new IOException("Truncated stream: incomplete nonce");
        }

        // Read ciphertext (plaintextLen + 16 bytes GCM tag)
        int ciphertextLen = plaintextLen + GCM_TAG_BYTES;
        var ciphertext = source.readNBytes(ciphertextLen);
        if (ciphertext.length < ciphertextLen) {
            throw new IOException("Truncated stream: incomplete ciphertext");
        }

        // Decrypt and verify
        currentChunk = AesGcmCipher.decrypt(key, new EncryptedPayload(nonce, ciphertext));
        chunkPos = 0;
        return true;
    }
}
