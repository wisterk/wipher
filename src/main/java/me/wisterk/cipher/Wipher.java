package me.wisterk.cipher;

import me.wisterk.cipher.crypto.KeyGenerator;
import me.wisterk.cipher.model.EncryptedPayload;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.model.WipherPreKeyBundle;
import me.wisterk.cipher.model.WipherPublicKey;
import me.wisterk.cipher.session.GroupSession;
import me.wisterk.cipher.session.WipherSession;
import me.wisterk.cipher.store.*;

import javax.sql.DataSource;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * **Wipher** — основной входной класс библиотеки Wisterk Cipher.
 * <p>
 * Предоставляет высокоуровневый API для end-to-end шифрования сообщений:
 * <ul>
 *     <li>Управление identity-ключами пользователя</li>
 *     <li>Установка pairwise E2E-сессий (X25519 + HKDF + AES-256-GCM)</li>
 *     <li>Групповые сессии на основе Sender Keys</li>
 *     <li>Шифрование и расшифровка сообщений (строки, байты, потоки)</li>
 *     <li>Поддержка различных хранилищ ключей</li>
 * </ul>
 * </p>
 *
 * <h3>Быстрый старт — 1-на-1 переписка</h3>
 * <pre>{@code
 * // Alice
 * var alice = Wipher.inMemory();           // или fileBased(), fromDatabase() и т.д.
 * var alicePub = alice.getPublicKey();
 *
 * // Bob
 * var bob = Wipher.inMemory();
 * var bobPub = bob.getPublicKey();
 *
 * // Установка сессий (каждый должен вызвать с публичным ключом другого)
 * alice.establishSession("bob", bobPub);
 * bob.establishSession("alice", alicePub);
 *
 * // Alice отправляет зашифрованное сообщение
 * var encrypted = alice.encrypt("bob", "Привет, Bob!");
 *
 * // Bob расшифровывает
 * String decrypted = bob.decrypt("alice", encrypted);
 * // → "Привет, Bob!"
 * }</pre>
 *
 * <h3>Групповая переписка (Sender Keys)</h3>
 * <pre>{@code
 * // Создаём группу на каждом устройстве
 * alice.createGroup("team");
 * bob.createGroup("team");
 *
 * // Обмениваемся sender-ключами через pairwise-сессии
 * var aliceKey = alice.getGroupSenderKey("team");
 * var bobKey   = bob.getGroupSenderKey("team");
 *
 * alice.addGroupMember("team", "bob", bobKey);
 * bob.addGroupMember("team", "alice", aliceKey);
 *
 * // Alice отправляет сообщение в группу
 * var msg = alice.encryptGroup("team", "Привет команде!");
 *
 * // Bob расшифровывает сообщение от Alice
 * String text = bob.decryptGroup("team", "alice", msg);
 * }</pre>
 *
 * <h3>Фабричные методы (рекомендуемые способы создания)</h3>
 * <ul>
 *     <li>{@link #inMemory()} — для тестов и временных сессий</li>
 *     <li>{@link #fileBased(Path)} — хранение на диске</li>
 *     <li>{@link #fromDatabase(DataSource)} — хранение в SQL БД</li>
 *     <li>{@link #fromEnvironments()} — ключи из переменных окружения</li>
 *     <li>{@link #encrypted(Wipher, String)} — обёртка с шифрованием на уровне приложения</li>
 * </ul>
 *
 * @see WipherSession (pairwise сессии)
 * @see GroupSession (групповые сессии)
 * @see WipherKeyStore (хранилища ключей)
 * @see EncryptedKeyStore (шифрование хранилища)
 */
public final class Wipher {

    private final WipherKeyStore keyStore;
    private final WipherKeyPair identityKeyPair;
    private final Map<String, GroupSession> groups = new ConcurrentHashMap<>();

    private Wipher(WipherKeyStore keyStore) {
        this.keyStore = keyStore;
        this.identityKeyPair = keyStore.loadIdentityKeyPair()
                .orElseGet(() -> {
                    var kp = KeyGenerator.generateKeyPair();
                    keyStore.saveIdentityKeyPair(kp);
                    return kp;
                });
    }

    // ── Factory methods ───────────────────────────────────

    /**
     * Создаёт Wipher с кастомным хранилищем ключей.
     */
    public static Wipher create(WipherKeyStore keyStore) {
        return new Wipher(keyStore);
    }

    /**
     * Создаёт Wipher с in-memory хранилищем (данные теряются при перезапуске).
     * Подходит для тестов и временных сессий.
     */
    public static Wipher inMemory() {
        return create(new InMemoryKeyStore());
    }

    /**
     * Создаёт Wipher с файловым хранилищем.
     */
    public static Wipher fileBased(Path baseDir) {
        return create(new FileKeyStore(baseDir));
    }

    /**
     * Создаёт Wipher с хранением в базе данных через JDBC DataSource.
     */
    public static Wipher fromDatabase(DataSource dataSource) {
        return create(new JdbcKeyStore(dataSource));
    }

    /**
     * Создаёт Wipher с хранением в базе данных по JDBC URL.
     */
    public static Wipher fromDatabase(String jdbcUrl, String username, String password) {
        return create(new JdbcKeyStore(jdbcUrl, username, password));
    }

    /**
     * Создаёт Wipher, загружая identity-ключи из переменных окружения.
     */
    public static Wipher fromEnvironments() {
        return create(new EnvironmentKeyStore());
    }

    /**
     * Оборачивает существующий Wipher в зашифрованное хранилище с мастер-паролем.
     * <p>
     * Все данные на диске/в БД будут дополнительно зашифрованы.
     * </p>
     */
    public static Wipher encrypted(Wipher wipher, String passphrase) {
        return new Wipher(EncryptedKeyStore.withPassphrase(wipher.keyStore, passphrase));
    }

    // ── Identity ──────────────────────────────────

    /**
     * Возвращает публичный ключ текущего пользователя.
     * <p>
     * Этот ключ можно безопасно передавать другим участникам.
     * </p>
     */
    public WipherPublicKey getPublicKey() {
        return identityKeyPair.toPublicKey();
    }

    /**
     * Генерирует pre-key bundle для оффлайн-установки сессий.
     *
     * @param preKeyCount количество одноразовых pre-keys
     */
    public WipherPreKeyBundle generatePreKeyBundle(int preKeyCount) {
        return KeyGenerator.generatePreKeyBundle(identityKeyPair, preKeyCount);
    }

    // ── Pairwise Sessions ─────────────────────────

    /**
     * Устанавливает E2E-сессию с собеседником.
     * <p>
     * Оба участника должны вызвать этот метод, передав публичный ключ другого.
     * </p>
     *
     * @param peerId        уникальный идентификатор собеседника
     * @param peerPublicKey публичный ключ собеседника
     */
    public void establishSession(String peerId, WipherPublicKey peerPublicKey) {
        var session = WipherSession.establish(identityKeyPair, peerPublicKey, peerId);
        keyStore.saveSession(peerId, session);
    }

    /**
     * Проверяет наличие активной сессии с собеседником.
     */
    public boolean hasSession(String peerId) {
        return keyStore.hasSession(peerId);
    }

    /**
     * Шифрует строку для указанного собеседника.
     */
    public EncryptedPayload encrypt(String peerId, String plaintext) {
        return getSession(peerId).encryptString(plaintext);
    }

    /**
     * Шифрует массив байтов для указанного собеседника.
     */
    public EncryptedPayload encrypt(String peerId, byte[] plaintext) {
        return getSession(peerId).encrypt(plaintext);
    }

    /**
     * Расшифровывает сообщение от собеседника в строку.
     */
    public String decrypt(String peerId, EncryptedPayload payload) {
        return getSession(peerId).decryptString(payload);
    }

    /**
     * Расшифровывает сообщение от собеседника в байты.
     */
    public byte[] decryptBytes(String peerId, EncryptedPayload payload) {
        return getSession(peerId).decrypt(payload);
    }

    // ── Streaming ──────────────────────────────────

    /**
     * Оборачивает plaintext InputStream в шифрующий поток (chunked AES-GCM).
     */
    public InputStream encryptStream(String peerId, InputStream plaintext) {
        return getSession(peerId).encryptStream(plaintext);
    }

    /**
     * Оборачивает encrypted InputStream в расшифровывающий поток.
     */
    public InputStream decryptStream(String peerId, InputStream encrypted) {
        return getSession(peerId).decryptStream(encrypted);
    }

    // ── Group Sessions ────────────────────────────

    /**
     * Создаёт новую групповую сессию.
     */
    public void createGroup(String groupId) {
        groups.put(groupId, new GroupSession(groupId));
    }

    /**
     * Возвращает sender-key текущего пользователя для группы.
     */
    public byte[] getGroupSenderKey(String groupId) {
        return getGroup(groupId).getOrCreateMySenderKey();
    }

    /**
     * Добавляет sender-key участника в групповую сессию.
     */
    public void addGroupMember(String groupId, String memberId, byte[] senderKey) {
        getGroup(groupId).addMemberKey(memberId, senderKey);
    }

    /**
     * Удаляет участника из группы и ротирует sender-key.
     * Новый ключ нужно разослать остальным участникам.
     */
    public byte[] removeGroupMember(String groupId, String memberId) {
        var group = getGroup(groupId);
        group.removeMember(memberId);
        return group.rotateSenderKey();
    }

    /**
     * Шифрует сообщение для группы (использует sender-key текущего пользователя).
     */
    public EncryptedPayload encryptGroup(String groupId, String plaintext) {
        return getGroup(groupId).encrypt(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Расшифровывает групповое сообщение от конкретного отправителя.
     */
    public String decryptGroup(String groupId, String senderId, EncryptedPayload payload) {
        return new String(getGroup(groupId).decrypt(senderId, payload),
                java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Шифрует поток для группы.
     */
    public InputStream encryptGroupStream(String groupId, InputStream plaintext) {
        return getGroup(groupId).encryptStream(plaintext);
    }

    /**
     * Расшифровывает поток из группы от конкретного отправителя.
     */
    public InputStream decryptGroupStream(String groupId, String senderId, InputStream encrypted) {
        return getGroup(groupId).decryptStream(senderId, encrypted);
    }

    // ── Internal helpers ─────────────────────────────────

    private WipherSession getSession(String peerId) {
        return keyStore.loadSession(peerId)
                .orElseThrow(() -> new IllegalStateException("No active session with peer: " + peerId));
    }

    private GroupSession getGroup(String groupId) {
        var group = groups.get(groupId);
        if (group == null) {
            throw new IllegalStateException("Group not found: " + groupId);
        }
        return group;
    }
}