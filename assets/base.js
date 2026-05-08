"use strict";

window.addEventListener("pageshow", () => {
	const buttonElements = document.getElementsByTagName("button");
	for (const buttonElement of buttonElements) {
		buttonElement.disabled = false;
	}
});

function setAuthSessionTokenCookie(authSessionToken) {
	setCookieWithExpiration("auth_session_token", authSessionToken, 86400);
}

function deleteAuthSessionTokenCookie() {
	setCookieWithExpiration("auth_session_token", "", 0);
}

function setSignupAuthSessionTokenCookie(signupAuthSessionToken) {
	setCookieWithExpiration("signup_session_token", signupAuthSessionToken, 86400);
}

function deleteSignupAuthSessionTokenCookie() {
	setCookieWithExpiration("signup_session_token", "", 0);
}

function setEmailAddressUpdateTokenCookie(emailAddressUpdateSessionToken) {
	setCookieWithExpiration(
		"email_address_update_session_token",
		emailAddressUpdateSessionToken,
		86400,
	);
}

function deleteEmailAddressUpdateTokenCookie() {
	setCookieWithExpiration("email_address_update_session_token", "", 0);
}

function setPasswordUpdateSessionTokenCookie(passwordUpdateSessionToken) {
	setCookieWithExpiration("password_update_session_token", passwordUpdateSessionToken, 86400);
}

function deletePasswordUpdateSessionTokenCookie() {
	setCookieWithExpiration("password_update_session_token", "", 0);
}

function setAccountDeletionTokenCookie(accountDeletionSessionToken) {
	setCookieWithExpiration("account_deletion_session_token", accountDeletionSessionToken, 86400);
}

function deleteAccountDeletionTokenCookie() {
	setCookieWithExpiration("account_deletion_session_token", "", 0);
}

function setPasswordResetTokenCookie(passwordResetSessionToken) {
	setCookieWithExpiration("password_reset_session_token", passwordResetSessionToken, 86400);
}

function deletePasswordResetTokenCookie() {
	setCookieWithExpiration("password_reset_session_token", "", 0);
}

function setCookieWithExpiration(name, value, maxAge) {
	if (window.location.protocol === "https:") {
		document.cookie = `${name}=${value}; Max-Age=${maxAge}; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `${name}=${value}; Max-Age=${maxAge}; SameSite=Lax; Path=/`;
	}
}

async function sendActionRequest(action, actionValuesJSONObject) {
	const requestBodyJSONObject = {
		action: action,
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let response;
	try {
		response = await fetch(request);
	} catch (error) {
		throw new Error("Failed to fetch request", {
			cause: error,
		});
	}

	if (!response.ok) {
		await response.body.cancel();
		throw new Error(`Unexpected response status code ${response.status}`);
	}

	const resultJSONObject = await response.json();
	if (!resultJSONObject.ok) {
		const result = {
			ok: false,
			errorCode: resultJSONObject.error_code,
		};
		return result;
	}

	const result = {
		ok: true,
		valuesJSONObject: resultJSONObject.values,
	};

	return result;
}
