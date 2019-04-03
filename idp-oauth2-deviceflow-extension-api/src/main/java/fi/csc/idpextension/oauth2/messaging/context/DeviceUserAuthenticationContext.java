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

package fi.csc.idpextension.oauth2.messaging.context;

import org.opensaml.messaging.context.BaseContext;

/**
 * Subcontext carrying user code. This context appears as a subcontext of the
 * inbound {@link MessageContext}.
 */
public class DeviceUserAuthenticationContext extends BaseContext {

	private String UserCode;

	private boolean userApproved;

	public boolean isUserApproved() {
		return userApproved;
	}

	public void setUserApproved(boolean userApproved) {
		this.userApproved = userApproved;
	}

	public String getUserCode() {
		return UserCode;
	}

	public void setUserCode(String userCode) {
		UserCode = userCode;
	}
}