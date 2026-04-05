package me.wisterk.cipher.stream;

import me.wisterk.cipher.crypto.AesGcmCipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Encrypting stream wrapper — reads plaintext from source, outputs ciphertext.
 *
 * Data is split into chunks (default 64KB). Each chunk is independently
 * encrypted with AES-256-GCM (own nonce + auth tag), so:
 * <ul>
 *     <li>Memory usage = one chunk, not the full stream</li>
 *     <li>Each chunk is tamper-proof (GCM tag verified independently)</li>
 *     <li>Streaming-friendly: start reading output before input is fully consumed</li>
 * </ul>
 *
 * <b>Wire format per chunk:</b>
 * <pre>
 * [4 bytes: plaintext length] [12 bytes: nonce] [N+16 bytes: ciphertext + GCM tag]
 * ...
 * [4 bytes: 0x00000000] — end-of-stream marker
 * </pre>
 */
public final class WipherEncryptingStream extends InputStream {

    /** Default chunk size: 64 KB of plaintext per encrypted block. */
    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024;

    private static final byte[] SENTINEL = new byte[0]; // EOF marker

    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>(8);
    private byte[] currentBuffer;
    private int bufferPos;
    private boolean eof;

    private WipherEncryptingStream() {}

    /**
     * Wrap a plaintext InputStream into an encrypting InputStream.
     *
     * @param key    32-byte AES key
     * @param source plaintext input
     * @return InputStream producing encrypted chunked output
     */
    public static WipherEncryptingStream wrap(byte[] key, InputStream source) {
        return wrap(key, source, DEFAULT_CHUNK_SIZE);
    }

    public static WipherEncryptingStream wrap(byte[] key, InputStream source, int chunkSize) {
        var stream = new WipherEncryptingStream();

        Thread.ofVirtual().start(() -> {
            try (source) {
                var buffer = new byte[chunkSize];
                int read;
                while ((read = source.read(buffer)) > 0) {
                    var plainChunk = new byte[read];
                    System.arraycopy(buffer, 0, plainChunk, 0, read);
                    var encrypted = AesGcmCipher.encrypt(key, plainChunk);

                    var out = new ByteArrayOutputStream(4 + 12 + encrypted.ciphertext().length);
                    out.write(intToBytes(read));
                    out.write(encrypted.nonce());
                    out.write(encrypted.ciphertext());

                    stream.queue.put(out.toByteArray());
                }
                // End marker
                var end = new ByteArrayOutputStream(4);
                end.write(intToBytes(0));
                stream.queue.put(end.toByteArray());
                stream.queue.put(SENTINEL);
            } catch (Exception e) {
                try { stream.queue.put(SENTINEL); } catch (InterruptedException ignored) {}
            }
        });

        return stream;
    }

    @Override
    public int read() throws IOException {
        if (eof) return -1;
        if (currentBuffer == null || bufferPos >= currentBuffer.length) {
            if (!loadNext()) return -1;
        }
        return currentBuffer[bufferPos++] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (eof) return -1;
        int totalRead = 0;
        while (totalRead < len) {
            if (currentBuffer == null || bufferPos >= currentBuffer.length) {
                if (!loadNext()) return totalRead > 0 ? totalRead : -1;
            }
            int available = currentBuffer.length - bufferPos;
            int toRead = Math.min(available, len - totalRead);
            System.arraycopy(currentBuffer, bufferPos, b, off + totalRead, toRead);
            bufferPos += toRead;
            totalRead += toRead;
        }
        return totalRead;
    }

    private boolean loadNext() {
        try {
            var data = queue.take();
            if (data == SENTINEL || data.length == 0) {
                eof = true;
                return false;
            }
            currentBuffer = data;
            bufferPos = 0;
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            eof = true;
            return false;
        }
    }

    static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
}
