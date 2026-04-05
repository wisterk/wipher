package me.wisterk.cipher.store;

import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory реализация хранилища ключей {@link WipherKeyStore}.
 * <p>
 * Все данные хранятся исключительно в оперативной памяти и полностью теряются при завершении процесса.
 * </p>
 *
 * <h3>Когда использовать</h3>
 * <ul>
 *     <li>Unit-тесты и интеграционные тесты</li>
 *     <li>CLI-инструменты и одноразовые утилиты</li>
 *     <li>Ephemeral сессии (serverless, короткоживущие контейнеры)</li>
 *     <li>Разработка и отладка (быстрый старт без настройки БД или файлов)</li>
 * </ul>
 *
 * <h3>Ограничения</h3>
 * <ul>
 *     <li>Identity key pair и все сессии исчезают после перезапуска приложения</li>
 *     <li>Не подходит для продакшена, где требуется persistence</li>
 *     <li>Thread-safe благодаря {@link ConcurrentHashMap} для сессий</li>
 * </ul>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * // Для тестов
 * var store = new InMemoryKeyStore();
 * var wipher = Wipher.create(store);
 *
 * // Или как временное хранилище
 * try (var tempStore = new InMemoryKeyStore()) {
 *     var tempWipher = Wipher.create(tempStore);
 *     // работа с временным шифрованием...
 * }
 * }</pre>
 *
 * <h3>Сравнение с другими хранилищами</h3>
 * <ul>
 *     <li>{@link EnvironmentKeyStore} — ключи из ENV, сессии в памяти</li>
 *     <li>{@link JdbcKeyStore} — постоянное хранение в SQL БД</li>
 *     <li>{@link EncryptedKeyStore} — обёртка для шифрования любого другого хранилища</li>
 * </ul>
 *
 * @see WipherKeyStore
 * @see Wipher
 * @see EncryptedKeyStore
 */
public final class InMemoryKeyStore implements WipherKeyStore {

    /**
     * Identity key pair текущего пользователя.
     * Хранится в volatile для безопасного доступа из разных потоков.
     */
    private volatile WipherKeyPair identityKeyPair;

    /**
     * Карта активных сессий с другими участниками.
     * Ключ — peerId, значение — установленная сессия.
     * Используется ConcurrentHashMap для thread-safety.
     */
    private final Map<String, WipherSession> sessions = new ConcurrentHashMap<>();

    /**
     * Сохраняет пару identity-ключей.
     * <p>
     * Перезаписывает предыдущие ключи, если они были.
     * </p>
     */
    @Override
    public void saveIdentityKeyPair(WipherKeyPair keyPair) {
        this.identityKeyPair = keyPair;
    }

    /**
     * Загружает сохранённую пару identity-ключей.
     *
     * @return Optional с ключевой парой или пустой Optional, если ключи ещё не сохранялись
     */
    @Override
    public Optional<WipherKeyPair> loadIdentityKeyPair() {
        return Optional.ofNullable(identityKeyPair);
    }

    /**
     * Сохраняет сессию с указанным собеседником.
     * <p>
     * Если сессия с таким peerId уже существовала — она перезаписывается.
     * </p>
     */
    @Override
    public void saveSession(String peerId, WipherSession session) {
        sessions.put(peerId, session);
    }

    /**
     * Загружает сессию по идентификатору собеседника.
     */
    @Override
    public Optional<WipherSession> loadSession(String peerId) {
        return Optional.ofNullable(sessions.get(peerId));
    }

    /**
     * Удаляет сессию с указанным собеседником.
     */
    @Override
    public void removeSession(String peerId) {
        sessions.remove(peerId);
    }

    /**
     * Проверяет наличие активной сессии с собеседником.
     */
    @Override
    public boolean hasSession(String peerId) {
        return sessions.containsKey(peerId);
    }
}