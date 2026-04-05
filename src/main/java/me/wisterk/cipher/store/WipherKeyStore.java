package me.wisterk.cipher.store;

import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import java.util.Optional;

/**
 * Service Provider Interface (SPI) для хранения криптографического состояния Wipher.
 * <p>
 * Определяет контракт для持久ного хранения:
 * <ul>
 *     <li>identity key pair (долгосрочные ключи пользователя)</li>
 *     <li>pairwise сессий (WipherSession) с другими участниками</li>
 * </ul>
 * </p>
 *
 * <h3>Поддерживаемые реализации</h3>
 * <ul>
 *     <li>{@link InMemoryKeyStore} — in-memory (для тестов и короткоживущих процессов)</li>
 *     <li>File-based KeyStore — сохранение в зашифрованные файлы на диске</li>
 *     <li>Database KeyStore — хранение в PostgreSQL / SQLite / Redis и т.д.</li>
 *     <li>Secure Enclave / Android Keystore / iOS Keychain — аппаратная защита</li>
 * </ul>
 *
 * <h3>Почему нужен отдельный интерфейс?</h3>
 * <ul>
 *     <li>Позволяет легко менять способ хранения без изменения логики шифрования</li>
 *     <li>Поддерживает разные уровни безопасности (in-memory → hardware-backed)</li>
 *     <li>Упрощает тестирование (можно подменить на mock)</li>
 *     <li>Обеспечивает persistence сессий между перезапусками приложения</li>
 * </ul>
 *
 * <h3>Пример кастомной реализации (упрощённо)</h3>
 * <pre>{@code
 * public class FileKeyStore implements WipherKeyStore {
 *     private final Path baseDir;
 *
 *     @Override
 *     public void saveIdentityKeyPair(WipherKeyPair keyPair) {
 *         // сохранить в зашифрованный файл
 *     }
 *
 *     @Override
 *     public Optional<WipherKeyPair> loadIdentityKeyPair() {
 *         // загрузить из файла
 *     }
 *
 *     // ... остальные методы
 * }
 * }</pre>
 *
 * <h3>Рекомендации по реализации</h3>
 * <ul>
 *     <li>Identity key pair должен сохраняться надёжно и никогда не удаляться</li>
 *     <li>Сессии можно удалять при выходе пользователя или очистке чата</li>
 *     <li>Рекомендуется шифровать хранилище мастер-ключом (derived from password / biometric)</li>
 *     <li>Методы должны быть thread-safe (используйте synchronized / ConcurrentHashMap)</li>
 *     <li>При ошибке чтения/записи бросайте {@link RuntimeException} или свой {@code WipherException}</li>
 * </ul>
 *
 * @see WipherSession
 * @see WipherKeyPair
 */
public interface WipherKeyStore {

    /**
     * Сохраняет пару identity-ключей текущего пользователя.
     * <p>
     * Этот ключ долгосрочный и должен сохраняться между запусками приложения.
     * </p>
     *
     * @param keyPair пара ключей (приватный + публичный)
     */
    void saveIdentityKeyPair(WipherKeyPair keyPair);

    /**
     * Загружает пару identity-ключей текущего пользователя.
     *
     * @return Optional с ключевой парой или пустой, если ключи ещё не созданы
     */
    Optional<WipherKeyPair> loadIdentityKeyPair();

    /**
     * Сохраняет установленную сессию с конкретным собеседником.
     *
     * @param peerId  идентификатор собеседника
     * @param session объект сессии
     */
    void saveSession(String peerId, WipherSession session);

    /**
     * Загружает сессию с указанным собеседником.
     *
     * @param peerId идентификатор собеседника
     * @return Optional с сессией или пустой, если сессия не найдена
     */
    Optional<WipherSession> loadSession(String peerId);

    /**
     * Удаляет сессию с указанным собеседником.
     * <p>
     * Используется при блокировке пользователя, очистке чата и т.д.
     * </p>
     *
     * @param peerId идентификатор собеседника
     */
    void removeSession(String peerId);

    /**
     * Проверяет, существует ли активная сессия с собеседником.
     *
     * @param peerId идентификатор собеседника
     * @return true, если сессия существует
     */
    boolean hasSession(String peerId);
}