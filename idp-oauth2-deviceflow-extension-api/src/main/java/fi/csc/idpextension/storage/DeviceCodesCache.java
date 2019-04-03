/*
 * Copyright (c) 2019 CSC- IT Center for Science, www.csc.fi
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
package fi.csc.idpextension.storage;

import java.io.IOException;

import javax.annotation.Nonnull;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.apache.commons.codec.digest.DigestUtils;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageCapabilitiesEx;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cache for storing {@link DeviceCodeObject} per User Code and state of the
 * request {@link DeviceStateObject} per Device Code.
 * <p>
 * This class is thread-safe and uses a synchronized method to prevent race
 * conditions within the underlying store (lacking an atomic "check and insert"
 * operation).
 * </p>
 */
@ThreadSafeAfterInit
public class DeviceCodesCache extends AbstractIdentifiableInitializableComponent {

	/** Logger. */
	private final Logger log = LoggerFactory.getLogger(DeviceCodesCache.class);

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
	 * @param storageService
	 *            backing store to use
	 */
	public void setStorage(@Nonnull final StorageService storageService) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

		storage = Constraint.isNotNull(storageService, "StorageService cannot be null");
		final StorageCapabilities caps = storage.getCapabilities();
		if (caps instanceof StorageCapabilitiesEx) {
			Constraint.isTrue(((StorageCapabilitiesEx) caps).isServerSide(), "StorageService cannot be client-side");
		}
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
	 * @param key
	 *            key to adjust
	 * @return key, either original or adjusted.
	 */
	private String adjustKey(@Nonnull String key) {
		StorageCapabilities caps = storage.getCapabilities();
		return key.length() > caps.getKeySize() ? DigestUtils.sha1Hex(key) : key;
	}

	/**
	 * Stores DeviceCodeObject keyed with user code. DeviceStateObject is created
	 * simultaneously, keyed by device code.
	 * 
	 * @param deviceCodeObject
	 *            DeviceCodeObject to store.
	 * @param userCode
	 *            key for storing the DeviceCodeObject.
	 * @param expiration
	 *            lifetime in milliseconds.
	 * @return true if stored successfully.
	 * @throws IOException
	 *             if something went wrong with storage.
	 */
	public synchronized boolean storeDeviceCode(@Nonnull DeviceCodeObject deviceCodeObject, @Nonnull String userCode,
			long expiration) throws IOException {
		String deviceCodeKey = adjustKey(userCode);
		if (!storage.create(CONTEXT_DEVICECODE, deviceCodeKey, deviceCodeObject.toJSONObject().toJSONString(),
				System.currentTimeMillis() + expiration)) {
			log.debug("User code collision for code {}", userCode);
			return false;
		}
		String deviceStateKey = adjustKey(deviceCodeObject.getDeviceCode());
		if (!storage.create(CONTEXT_STATE, deviceStateKey, new DeviceStateObject().toJSONObject().toJSONString(),
				System.currentTimeMillis() + expiration)) {
			log.debug("Device code collision for code {}", deviceCodeObject.getDeviceCode());
			return false;
		}
		return true;
	}

	/**
	 * Get DeviceCodeObject keyed with user code.
	 * 
	 * @param userCode
	 *            key to DeviceCodeObject.
	 * @return DeviceCodeObject keyed with user code. Null if not located.
	 * @throws IOException
	 *             if something went wrong with storage.
	 * @throws ParseException
	 *             if DeviceCodeObject was not parsed successfully.
	 */
	@SuppressWarnings("rawtypes")
	public synchronized DeviceCodeObject getDeviceCode(@Nonnull String userCode) throws IOException, ParseException {
		String deviceCodeKey = adjustKey(userCode);
		StorageRecord entry = storage.read(CONTEXT_DEVICECODE, deviceCodeKey);
		if (entry == null) {
			return null;
		}
		Object obj = new JSONParser(JSONParser.MODE_PERMISSIVE).parse(entry.getValue());
		if (obj instanceof JSONObject) {
			return DeviceCodeObject.fromJSONObject((JSONObject) obj);
		}
		throw new IOException("Storage record could not be parsed as a JSONObject");
	}

	/**
	 * Get DeviceStateObject, keyed by device code.
	 * 
	 * @param deviceCode
	 *            key to DeviceStateObject
	 * @return DeviceStateObject keyed with device code. Null if not located.
	 * @throws IOException
	 *             if something went wrong with storage.
	 * @throws ParseException
	 *             if DeviceCodeObject was not parsed successfully.
	 */
	@SuppressWarnings("rawtypes")
	public synchronized DeviceStateObject getDeviceState(@Nonnull String deviceCode)
			throws IOException, ParseException {
		String deviceStateKey = adjustKey(deviceCode);
		StorageRecord entry = storage.read(CONTEXT_STATE, deviceStateKey);
		if (entry == null) {
			return null;
		}
		Object obj = new JSONParser(JSONParser.MODE_PERMISSIVE).parse(entry.getValue());
		if (obj instanceof JSONObject) {
			return DeviceStateObject.fromJSONObject((JSONObject) obj);
		}
		throw new IOException("Storage record could not be parsed as a JSONObject");
	}

	/**
	 * Update DeviceStateObject, keyed by device code.
	 * 
	 * @param deviceCode
	 *            key to store DeviceStateObject by.
	 * @param deviceStateObject
	 *            DeviceStateObject containing updated information.
	 * @param expiration
	 *            lifetime in milliseconds.
	 * @return true if the object was successfully updated.
	 * @throws IOException
	 *             if something went wrong with storage.
	 * @throws ParseException
	 *             if DeviceCodeObject was not parsed successfully.
	 */
	public synchronized boolean updateDeviceState(@Nonnull String deviceCode,
			@Nonnull DeviceStateObject deviceStateObject, long expiration) throws IOException, ParseException {
		String deviceStateKey = adjustKey(deviceCode);
		return storage.update(CONTEXT_STATE, deviceStateKey, deviceStateObject.toJSONObject().toJSONString(),
				System.currentTimeMillis() + expiration);
	}

}