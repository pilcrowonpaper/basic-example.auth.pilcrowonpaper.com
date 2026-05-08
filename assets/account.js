const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.auth_session_token;

const updateEmailAddressButtonElement = document.getElementById("update-email-address-button");
updateEmailAddressButtonElement.addEventListener("click", handleUpdateEmailAddressButtonClickEvent);

const updatePasswordButtonElement = document.getElementById("update-password-button");
updatePasswordButtonElement.addEventListener("click", handleUpdatePasswordButtonClickEvent);

const signOutButtonElement = document.getElementById("sign-out-button");
signOutButtonElement.addEventListener("click", handleSignOutClickEvent);

const signOutAllDevicesButtonElement = document.getElementById("sign-out-all-devices-button");
signOutAllDevicesButtonElement.addEventListener("click", handleSignOutAllDevicesButtonClickEvent);

const deleteAccountButton = document.getElementById("delete-account-button");
deleteAccountButton.addEventListener("click", handleDeleteAccountButtonClickEvent);

async function handleUpdateEmailAddressButtonClickEvent() {
	updateEmailAddressButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_email_address_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			updateEmailAddressButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	setEmailAddressUpdateTokenCookie(
		actionResult.valuesJSONObject.email_address_update_session_token,
	);

	window.location.href = "/update-email-address/verify-password";
}

async function handleUpdatePasswordButtonClickEvent() {
	updatePasswordButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_password_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updatePasswordButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			updatePasswordButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updatePasswordButtonElement.disabled = false;
		return;
	}

	setPasswordUpdateSessionTokenCookie(actionResult.valuesJSONObject.password_update_session_token);

	window.location.href = "/update-password/verify-password";
}

async function handleSignOutClickEvent() {
	signOutButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("sign_out", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			signOutButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	deleteAuthSessionTokenCookie();

	window.location.href = "/sign-in";
}

async function handleSignOutAllDevicesButtonClickEvent() {
	const confirmed = confirm("Do you want to sign out of all devices?");
	if (!confirmed) {
		return;
	}

	signOutAllDevicesButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("sign_out_all_devices", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			signOutAllDevicesButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	deleteAuthSessionTokenCookie();

	window.location.href = "/sign-in";
}

async function handleDeleteAccountButtonClickEvent() {
	deleteAccountButton.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButton.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			deleteAccountButton.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButton.disabled = false;
		return;
	}

	setAccountDeletionTokenCookie(actionResult.valuesJSONObject.account_deletion_session_token);

	window.location.href = "/delete-account/verify-password";
}
