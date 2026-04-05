package me.wisterk.cipher;

import me.wisterk.cipher.model.EncryptedPayload;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full E2E simulation:
 *   Alice (socket) ──► Relay Server (socket) ──► Bob (socket)
 *
 * Server forwards encrypted bytes — CANNOT read content.
 */
class WipherSocketTest {

    @Test
    @Timeout(10)
    void aliceSendsBobEncryptedMessageAndFile() throws Exception {

        var alice = Wipher.inMemory();
        var bob = Wipher.inMemory();

        // Key exchange (pre-established — in real app happens via server)
        alice.establishSession("bob", bob.getPublicKey());
        bob.establishSession("alice", alice.getPublicKey());

        var bobReceivedText = new AtomicReference<String>();
        var bobReceivedFileName = new AtomicReference<String>();
        var bobReceivedFileContent = new AtomicReference<byte[]>();
        var serverLog = new AtomicReference<String>();
        var bobDone = new CountDownLatch(1);

        // ── Relay Server ──
        var server = new ServerSocket(0);
        int port = server.getLocalPort();

        Thread.ofVirtual().start(() -> {
            try {
                // Accept both: order = Bob first, then Alice
                var conn1 = server.accept();
                var conn2 = server.accept();

                // conn1 = Bob (receiver), conn2 = Alice (sender)
                var fromAlice = new BufferedReader(new InputStreamReader(conn2.getInputStream()));
                var toBob = new PrintWriter(conn1.getOutputStream(), true);

                var log = new StringBuilder();
                String line;
                while ((line = fromAlice.readLine()) != null) {
                    log.append(line).append("\n");
                    toBob.println(line);
                }
                serverLog.set(log.toString());
                conn1.close();
                conn2.close();
            } catch (Exception ignored) {}
        });

        // ── Bob connects first (receiver) ──
        var bobSocket = new Socket("localhost", port);
        var bobReader = new BufferedReader(new InputStreamReader(bobSocket.getInputStream()));

        Thread.ofVirtual().start(() -> {
            try {
                String line = bobReader.readLine();
                if (line != null && line.startsWith("MSG ")) {
                    bobReceivedText.set(bob.decrypt("alice", EncryptedPayload.fromBase64(line.substring(4))));
                }

                line = bobReader.readLine();
                if (line != null && line.startsWith("FILE ")) {
                    var parts = line.split(" ", 3);
                    bobReceivedFileName.set(bob.decrypt("alice", EncryptedPayload.fromBase64(parts[1])));
                    bobReceivedFileContent.set(bob.decryptBytes("alice", EncryptedPayload.fromBase64(parts[2])));
                }
                bobSocket.close();
                bobDone.countDown();
            } catch (Exception e) { fail("Bob error: " + e.getMessage()); }
        });

        // ── Alice connects second (sender) ──
        Thread.sleep(50); // ensure Bob connected first
        var aliceSocket = new Socket("localhost", port);
        var writer = new PrintWriter(aliceSocket.getOutputStream(), true);

        // Send encrypted text
        writer.println("MSG " + alice.encrypt("bob", "Hello Bob! Here's the contract.").toBase64());

        // Send encrypted file
        var fileBytes = "CONFIDENTIAL\nPage 1: Secret data\nPage 2: More secrets".getBytes(StandardCharsets.UTF_8);
        writer.println("FILE " + alice.encrypt("bob", "contract.pdf").toBase64()
                + " " + alice.encrypt("bob", fileBytes).toBase64());

        aliceSocket.close();

        // ── Wait and verify ──
        assertTrue(bobDone.await(5, TimeUnit.SECONDS), "Bob must finish");
        server.close();

        assertEquals("Hello Bob! Here's the contract.", bobReceivedText.get());
        assertEquals("contract.pdf", bobReceivedFileName.get());
        assertArrayEquals(fileBytes, bobReceivedFileContent.get());

        // Server saw ONLY ciphertext
        assertFalse(serverLog.get().contains("Hello Bob"));
        assertFalse(serverLog.get().contains("contract.pdf"));
        assertFalse(serverLog.get().contains("CONFIDENTIAL"));

        System.out.println("═══ SERVER SAW ═══");
        for (var l : serverLog.get().split("\n")) {
            System.out.println("  " + l.substring(0, Math.min(80, l.length())) + "...");
        }
        System.out.println("═══ BOB DECRYPTED ═══");
        System.out.println("  Text: " + bobReceivedText.get());
        System.out.println("  File: " + bobReceivedFileName.get());
        System.out.println("  Content: " + new String(bobReceivedFileContent.get(), StandardCharsets.UTF_8));
    }

    @Test
    @Timeout(5)
    void groupChatWithKeyRotation() {
        var alice = Wipher.inMemory();
        var bob = Wipher.inMemory();
        var katya = Wipher.inMemory();

        alice.createGroup("team");
        bob.createGroup("team");
        katya.createGroup("team");

        // Distribute sender keys
        alice.addGroupMember("team", "bob", bob.getGroupSenderKey("team"));
        alice.addGroupMember("team", "katya", katya.getGroupSenderKey("team"));
        bob.addGroupMember("team", "alice", alice.getGroupSenderKey("team"));
        bob.addGroupMember("team", "katya", katya.getGroupSenderKey("team"));
        katya.addGroupMember("team", "alice", alice.getGroupSenderKey("team"));
        katya.addGroupMember("team", "bob", bob.getGroupSenderKey("team"));

        // Broadcast
        var msg = alice.encryptGroup("team", "Hello team!");
        assertEquals("Hello team!", bob.decryptGroup("team", "alice", msg));
        assertEquals("Hello team!", katya.decryptGroup("team", "alice", msg));

        // Remove Katya → rotate
        var newKey = alice.removeGroupMember("team", "katya");
        bob.removeGroupMember("team", "katya");
        bob.addGroupMember("team", "alice", newKey);

        var secret = alice.encryptGroup("team", "Katya can't read this");
        assertEquals("Katya can't read this", bob.decryptGroup("team", "alice", secret));

        boolean katyaFailed = false;
        try { katya.decryptGroup("team", "alice", secret); } catch (Exception e) { katyaFailed = true; }
        assertTrue(katyaFailed, "Katya must NOT read after removal");

        System.out.println("Group E2E: 3 members, key rotation — passed");
    }

    @Test
    @Timeout(5)
    void eavesdropperCannotDecrypt() {
        var alice = Wipher.inMemory();
        var bob = Wipher.inMemory();
        var eve = Wipher.inMemory();

        alice.establishSession("bob", bob.getPublicKey());
        bob.establishSession("alice", alice.getPublicKey());
        eve.establishSession("alice", alice.getPublicKey());
        eve.establishSession("bob", bob.getPublicKey());

        var encrypted = alice.encrypt("bob", "Nuclear launch codes: 12345");

        // Bob decrypts
        assertEquals("Nuclear launch codes: 12345", bob.decrypt("alice", encrypted));

        // Eve cannot
        boolean eveFailed = false;
        try { eve.decrypt("alice", encrypted); } catch (Exception e) { eveFailed = true; }
        assertTrue(eveFailed, "Eve must NOT decrypt with only public keys");

        System.out.println("Eavesdropper: public keys intercepted, still can't decrypt — passed");
    }
}
