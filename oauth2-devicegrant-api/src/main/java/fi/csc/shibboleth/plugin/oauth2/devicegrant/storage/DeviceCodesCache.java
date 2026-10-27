/*
 * Copyright (c) 2019-2024 CSC- IT Center for Science, www.csc.fi
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fi.csc.shibboleth.plugin.oauth2.devicegrant.storage;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;

import org.apache.commons.codec.digest.DigestUtils;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.opensaml.storage.VersionMismatchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cache for storing {@link DeviceCodeObject} per User Code and state of the request {@link DeviceStateObject} per
 * Device Code.
 * <p>
 * This class is thread-safe and uses a synchronised method to prevent race conditions within the underlying store
 * (lacking an atomic "check and insert" operation).
 * </p>
 */
@ThreadSafeAfterInit
public class DeviceCodesCache extends AbstractIdentifiableInitializableComponent {

    /**
     * ID of device code object context.
     */
    @Nonnull
    @NotEmpty
    public static final String CONTEXT_DEVICECODE = DeviceCodesCache.class.getName() + ".DEVICE_CODE";

    /**
     * ID of device state object context.
     */
    @Nonnull
    @NotEmpty
    public static final String CONTEXT_STATE = DeviceCodesCache.class.getName() + ".STATE";

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(DeviceCodesCache.class);

    /** Backing storage for the cache. */
    private StorageService storage;

    /**
     * Get the backing store for the cache.
     * 
     * @return the backing store.
     */
    @NonnullAfterInit
    public StorageService getStorage() {
        return storage;
    }

    /**
     * Set the backing store for the cache.
     * 
     * @param storageService backing store to use
     */
    public void setStorage(@Nonnull final StorageService storageService) {
        checkSetterPreconditions();

        storage = Constraint.isNotNull(storageService, "StorageService cannot be null");
        final StorageCapabilities caps = storage.getCapabilities();
        Constraint.isTrue(caps.isServerSide(), "StorageService cannot be client-side");
        Constraint.isTrue(CONTEXT_DEVICECODE.length() <= caps.getContextSize(),
                "Context " + CONTEXT_DEVICECODE.length() + " too long for StorageService " + caps.getContextSize());
        Constraint.isTrue(CONTEXT_STATE.length() <= caps.getContextSize(),
                "Context " + CONTEXT_STATE.length() + " too long for StorageService " + caps.getContextSize());
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        if (storage == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }

    }

    /**
     * Adjusts the key to smaller size if needed.
     * 
     * @param key key to adjust
     * @return key, either original or adjusted.
     */
    private String adjustKey(@Nonnull final String key) {
        final StorageCapabilities caps = storage.getCapabilities();
        return key.length() > caps.getKeySize() ? DigestUtils.sha1Hex(key) : key;
    }

    /**
     * Stores DeviceCodeObject keyed with user code. DeviceStateObject is created simultaneously, keyed by device code.
     * 
     * @param deviceCodeObject DeviceCodeObject to store.
     * @param userCode key for storing the DeviceCodeObject.
     * @param expiration lifetime in milliseconds.
     * @return true if stored successfully.
     * @throws IOException if something went wrong with storage.
     */
    public synchronized boolean storeDeviceCode(@Nonnull final DeviceCodeObject deviceCodeObject,
            @Nonnull final String userCode, final long expiration) throws IOException {
        return storeDeviceCode(deviceCodeObject, userCode, expiration, null);
    }

    /**
     * Stores DeviceCodeObject keyed with user code. DeviceStateObject is created simultaneously, keyed by device code.
     * 
     * @param deviceCodeObject DeviceCodeObject to store.
     * @param userCode key for storing the DeviceCodeObject.
     * @param expiration lifetime in milliseconds.
     * @param interval polling interval in milliseconds, null for none.
     * @return true if stored successfully.
     * @throws IOException if something went wrong with storage.
     */
    public synchronized boolean storeDeviceCode(@Nonnull final DeviceCodeObject deviceCodeObject,
            @Nonnull final String userCode, final long expiration, @Nullable final Long interval) throws IOException {
        final String deviceCodeKey = adjustKey(userCode);
        if (!storage.create(CONTEXT_DEVICECODE, deviceCodeKey, deviceCodeObject.toJSONObject().toJSONString(),
                System.currentTimeMillis() + expiration)) {
            log.debug("User code collision");
            return false;
        }
        final String deviceStateKey = adjustKey(deviceCodeObject.getDeviceCode());
        final DeviceStateObject deviceStateObject = new DeviceStateObject(DeviceStateObject.State.PENDING, null, null,
                deviceCodeObject.getClientID().getValue(), interval, null);
        if (!storage.create(CONTEXT_STATE, deviceStateKey, deviceStateObject.toJSONObject().toJSONString(),
                System.currentTimeMillis() + expiration)) {
            log.debug("Device code collision");
            return false;
        }
        return true;
    }

    /**
     * Get DeviceCodeObject keyed with user code.
     * 
     * @param userCode key to DeviceCodeObject.
     * @return DeviceCodeObject keyed with user code. Null if not located.
     * @throws IOException if something went wrong with storage.
     * @throws ParseException if DeviceCodeObject was not parsed successfully.
     */
    @SuppressWarnings("rawtypes")
    public synchronized DeviceCodeObject getDeviceCode(@Nonnull final String userCode)
            throws IOException, ParseException {
        final String deviceCodeKey = adjustKey(userCode);
        final StorageRecord entry = storage.read(CONTEXT_DEVICECODE, deviceCodeKey);
        if (entry == null) {
            return null;
        }
        final Object obj = new JSONParser(JSONParser.MODE_PERMISSIVE).parse(entry.getValue());
        if (obj instanceof JSONObject) {
            return DeviceCodeObject.fromJSONObject((JSONObject) obj);
        }
        throw new IOException("Storage record could not be parsed as a JSONObject");
    }

    /**
     * Get DeviceStateObject, keyed by device code.
     * 
     * @param deviceCode key to DeviceStateObject
     * @return DeviceStateObject keyed with device code. Null if not located.
     * @throws IOException if something went wrong with storage.
     * @throws ParseException if DeviceCodeObject was not parsed successfully.
     */
    public synchronized DeviceStateObject getDeviceState(@Nonnull final String deviceCode)
            throws IOException, ParseException {
        final Pair<Long, DeviceStateObject> versionedState = getVersionedDeviceState(deviceCode);
        return versionedState != null ? versionedState.getSecond() : null;
    }

    /**
     * Get DeviceStateObject and the version of its storage record, keyed by device code.
     * 
     * @param deviceCode key to DeviceStateObject
     * @return version and DeviceStateObject keyed with device code. Null if not located.
     * @throws IOException if something went wrong with storage.
     * @throws ParseException if DeviceStateObject was not parsed successfully.
     */
    @Nullable
    public synchronized Pair<Long, DeviceStateObject> getVersionedDeviceState(@Nonnull final String deviceCode)
            throws IOException, ParseException {
        final String deviceStateKey = adjustKey(deviceCode);
        final StorageRecord<?> entry = storage.read(CONTEXT_STATE, deviceStateKey);
        if (entry == null) {
            return null;
        }
        final Object obj = new JSONParser(JSONParser.MODE_PERMISSIVE).parse(entry.getValue());
        if (obj instanceof JSONObject) {
            return new Pair<>(entry.getVersion(), DeviceStateObject.fromJSONObject((JSONObject) obj));
        }
        throw new IOException("Storage record could not be parsed as a JSONObject");
    }

    /**
     * Remove DeviceCodeObject, keyed by user code.
     * 
     * @param userCode key the DeviceCodeObject is stored by.
     * @return true if the object was removed, false if it did not exist.
     * @throws IOException if something went wrong with storage.
     */
    public synchronized boolean removeDeviceCode(@Nonnull final String userCode) throws IOException {
        return storage.delete(CONTEXT_DEVICECODE, adjustKey(userCode));
    }

    /**
     * Update DeviceStateObject, keyed by device code. The expiration of the stored record is kept.
     * 
     * @param deviceCode key to store DeviceStateObject by.
     * @param deviceStateObject DeviceStateObject containing updated information.
     * @return true if the object was successfully updated.
     * @throws IOException if something went wrong with storage.
     */
    public synchronized boolean updateDeviceState(@Nonnull final String deviceCode,
            @Nonnull final DeviceStateObject deviceStateObject) throws IOException {
        final String deviceStateKey = adjustKey(deviceCode);
        final StorageRecord<?> record = storage.read(CONTEXT_STATE, deviceStateKey);
        if (record == null) {
            return false;
        }
        return storage.update(CONTEXT_STATE, deviceStateKey, deviceStateObject.toJSONObject().toJSONString(),
                record.getExpiration());
    }

    /**
     * Update DeviceStateObject, keyed by device code, if its storage record still has the given version. The
     * expiration of the stored record is kept.
     * 
     * @param deviceCode key to store DeviceStateObject by.
     * @param deviceStateObject DeviceStateObject containing updated information.
     * @param version version of the storage record the update is based on.
     * @return true if the object was successfully updated, false if it did not exist.
     * @throws IOException if something went wrong with storage.
     * @throws VersionMismatchException if the storage record has another version.
     */
    public synchronized boolean updateDeviceState(@Nonnull final String deviceCode,
            @Nonnull final DeviceStateObject deviceStateObject, final long version)
            throws IOException, VersionMismatchException {
        final String deviceStateKey = adjustKey(deviceCode);
        final StorageRecord<?> record = storage.read(CONTEXT_STATE, deviceStateKey);
        if (record == null) {
            return false;
        }
        return storage.updateWithVersion(version, CONTEXT_STATE, deviceStateKey,
                deviceStateObject.toJSONObject().toJSONString(), record.getExpiration()) != null;
    }

}