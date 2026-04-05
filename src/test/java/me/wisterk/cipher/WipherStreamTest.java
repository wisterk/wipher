package me.wisterk.cipher;

import me.wisterk.cipher.stream.WipherDecryptingStream;
import me.wisterk.cipher.stream.WipherEncryptingStream;
import me.wisterk.cipher.crypto.KeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for streaming encryption/decryption.
 * Verifies that large data can be encrypted/decrypted without
 * loading the entire content into memory at once.
 */
class WipherStreamTest {

    @Test
    @Timeout(5)
    void encryptDecryptSmallStream() throws IOException {
        var key = KeyGenerator.generateSymmetricKey();
        var original = "Hello, streaming encryption!".getBytes();

        var encrypted = WipherEncryptingStream.wrap(key, new ByteArrayInputStream(original));
        var decrypted = WipherDecryptingStream.wrap(key, encrypted);

        assertArrayEquals(original, decrypted.readAllBytes());
    }

    @Test
    @Timeout(10)
    void encryptDecryptLargeStream() throws IOException {
        var key = KeyGenerator.generateSymmetricKey();

        // 1 MB of random data — streamed in 64KB chunks
        var original = new byte[1024 * 1024];
        new SecureRandom().nextBytes(original);

        var encrypted = WipherEncryptingStream.wrap(key, new ByteArrayInputStream(original));
        var decrypted = WipherDecryptingStream.wrap(key, encrypted);

        var result = decrypted.readAllBytes();
        assertArrayEquals(original, result);

        System.out.println("Streamed 1 MB: encrypted → decrypted OK (" +
                (1024 * 1024) + " bytes in " +
                (1024 * 1024 / WipherEncryptingStream.DEFAULT_CHUNK_SIZE) + " chunks)");
    }

    @Test
    @Timeout(5)
    void encryptDecryptViaWipherApi() throws IOException {
        var alice = Wipher.inMemory();
        var bob = Wipher.inMemory();

        alice.establishSession("bob", bob.getPublicKey());
        bob.establishSession("alice", alice.getPublicKey());

        var fileContent = "This is a large document that would be streamed in production.".repeat(1000);
        var original = fileContent.getBytes();

        // Alice encrypts stream
        var encrypted = alice.encryptStream("bob", new ByteArrayInputStream(original));

        // Bob decrypts stream
        var decrypted = bob.decryptStream("alice", encrypted);

        assertArrayEquals(original, decrypted.readAllBytes());
        System.out.println("Wipher streaming API: " + original.length + " bytes — passed");
    }

    @Test
    @Timeout(5)
    void readByteByByte() throws IOException {
        var key = KeyGenerator.generateSymmetricKey();
        var original = "Byte-by-byte reading test".getBytes();

        var encrypted = WipherEncryptingStream.wrap(key, new ByteArrayInputStream(original));
        var decrypted = WipherDecryptingStream.wrap(key, encrypted);

        var result = new byte[original.length];
        for (int i = 0; i < original.length; i++) {
            int b = decrypted.read();
            assertNotEquals(-1, b, "Unexpected EOF at byte " + i);
            result[i] = (byte) b;
        }
        assertEquals(-1, decrypted.read(), "Should be EOF");
        assertArrayEquals(original, result);
    }

    @Test
    @Timeout(5)
    void wrongKeyCannotDecryptStream() throws IOException {
        var key1 = KeyGenerator.generateSymmetricKey();
        var key2 = KeyGenerator.generateSymmetricKey();

        var original = "Secret streaming data".getBytes();
        var encrypted = WipherEncryptingStream.wrap(key1, new ByteArrayInputStream(original));

        var decrypted = WipherDecryptingStream.wrap(key2, encrypted);
        assertThrows(Exception.class, decrypted::readAllBytes);
    }

    @Test
    @Timeout(5)
    void customChunkSize() throws IOException {
        var key = KeyGenerator.generateSymmetricKey();
        var original = new byte[10_000]; // 10KB
        new SecureRandom().nextBytes(original);

        // Use tiny 1KB chunks
        var encrypted = WipherEncryptingStream.wrap(key, new ByteArrayInputStream(original), 1024);
        var decrypted = WipherDecryptingStream.wrap(key, encrypted);

        assertArrayEquals(original, decrypted.readAllBytes());
        System.out.println("Custom chunk size (1KB): 10KB data in 10 chunks — passed");
    }
}
