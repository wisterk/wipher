package me.wisterk.cipher.store;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

/**
 * Файловое хранилище ключей — сохраняет identity-ключи и сессии на диск.
 * <p>
 * Структура директории:
 * <pre>
 * baseDir/
 * ├── identity.pub        — публичный ключ X25519 (X.509 encoded)
 * ├── identity.key        — приватный ключ X25519 (PKCS#8 encoded)
 * └── sessions/
 *     ├── alice.session    — сериализованная сессия с alice
 *     ├── bob.session
 *     └── ...
 * </pre>
 * </p>
 *
 * <h3>Важные замечания по безопасности</h3>
 * <ul>
 *     <li>Ключи хранятся в открытом виде (raw bytes) — <strong>не используйте в продакшене без дополнительной защиты</strong></li>
 *     <li>Рекомендуется комбинировать с {@link EncryptedKeyStore} или использовать OS-level шифрование (FileVault, LUKS, eCryptfs)</li>
 *     <li>Директория должна иметь строгие права доступа (chmod 700)</li>
 * </ul>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * var store = new FileKeyStore(Path.of(System.getProperty("user.home"), ".wipher"));
 * var wipher = Wipher.create(store);
 * }</pre>
 *
 * <h3>Особенности реализации</h3>
 * <ul>
 *     <li>Автоматически создаёт директорию {@code sessions/} при инициализации</li>
 *     <li>Имена файлов для сессий санитизируются (замена недопустимых символов на `_`)</li>
 *     <li>Все операции с файлами оборачиваются в {@link WipherException}</li>
 *     <li>Загрузка identity-ключа происходит только при первом обращении (лениво)</li>
 * </ul>
 *
 * @see WipherKeyStore
 * @see EncryptedKeyStore (рекомендуется для продакшена)
 * @see InMemoryKeyStore
 */
public final class FileKeyStore implements WipherKeyStore {

    private static final String IDENTITY_PUB = "identity.pub";
    private static final String IDENTITY_KEY = "identity.key";
    private static final String SESSIONS_DIR = "sessions";

    private final Path baseDir;

    /**
     * Создаёт файловое хранилище по указанному пути.
     * <p>
     * Если директория не существует — она будет создана.
     * </p>
     *
     * @param baseDir базовая директория для хранения ключей
     */
    public FileKeyStore(Path baseDir) {
        this.baseDir = baseDir;
        try {
            Files.createDirectories(baseDir.resolve(SESSIONS_DIR));
        } catch (IOException e) {
            throw new WipherException("Cannot create key store directory: " + baseDir, e);
        }
    }

    /**
     * Сохраняет пару identity-ключей на диск.
     * <p>
     * Публичный ключ сохраняется в {@code identity.pub}, приватный — в {@code identity.key}.
     * </p>
     */
    @Override
    public void saveIdentityKeyPair(WipherKeyPair keyPair) {
        writeBytes(baseDir.resolve(IDENTITY_PUB), keyPair.publicKey().getEncoded());
        writeBytes(baseDir.resolve(IDENTITY_KEY), keyPair.privateKey().getEncoded());
    }

    /**
     * Загружает пару identity-ключей с диска.
     * <p>
     * Возвращает пустой Optional, если файлы ключей не найдены.
     * </p>
     */
    @Override
    public Optional<WipherKeyPair> loadIdentityKeyPair() {
        var pubPath = baseDir.resolve(IDENTITY_PUB);
        var keyPath = baseDir.resolve(IDENTITY_KEY);

        if (!Files.exists(pubPath) || !Files.exists(keyPath)) {
            return Optional.empty();
        }

        try {
            var kf = KeyFactory.getInstance("X25519");

            var pub = kf.generatePublic(new X509EncodedKeySpec(readBytes(pubPath)));
            var priv = kf.generatePrivate(new PKCS8EncodedKeySpec(readBytes(keyPath)));

            return Optional.of(new WipherKeyPair(pub, priv));
        } catch (Exception e) {
            throw new WipherException("Failed to load identity key pair from file store", e);
        }
    }

    /**
     * Сохраняет сессию с собеседником в файл {@code sessions/{peerId}.session}.
     */
    @Override
    public void saveSession(String peerId, WipherSession session) {
        writeBytes(sessionPath(peerId), session.serialize());
    }

    /**
     * Загружает сессию из файла.
     * <p>
     * Возвращает пустой Optional, если файл сессии не существует.
     * </p>
     */
    @Override
    public Optional<WipherSession> loadSession(String peerId) {
        var path = sessionPath(peerId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        try {
            return Optional.of(WipherSession.deserialize(readBytes(path)));
        } catch (Exception e) {
            throw new WipherException("Failed to load session for peer: " + peerId, e);
        }
    }

    /**
     * Удаляет файл сессии.
     */
    @Override
    public void removeSession(String peerId) {
        try {
            Files.deleteIfExists(sessionPath(peerId));
        } catch (IOException e) {
            throw new WipherException("Failed to delete session file for peer: " + peerId, e);
        }
    }

    /**
     * Проверяет существование файла сессии.
     */
    @Override
    public boolean hasSession(String peerId) {
        return Files.exists(sessionPath(peerId));
    }

    /**
     * Возвращает путь к файлу сессии с санитизацией имени.
     * <p>
     * Заменяет все недопустимые символы на `_` для безопасности файловой системы.
     * </p>
     */
    private Path sessionPath(String peerId) {
        var safeName = peerId.replaceAll("[^a-zA-Z0-9_\\-@.]", "_");
        return baseDir.resolve(SESSIONS_DIR).resolve(safeName + ".session");
    }

    /**
     * Читает все байты из файла.
     */
    private static byte[] readBytes(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new WipherException("Failed to read file: " + path, e);
        }
    }

    /**
     * Записывает байты в файл (перезаписывает, если существует).
     */
    private static void writeBytes(Path path, byte[] data) {
        try {
            Files.write(path, data);
        } catch (IOException e) {
            throw new WipherException("Failed to write file: " + path, e);
        }
    }
}