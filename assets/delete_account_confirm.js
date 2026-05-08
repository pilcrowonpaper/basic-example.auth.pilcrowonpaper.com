const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.auth_session_token;
const accountDeletionSessionToken = pageDataJSONObject.account_deletion_session_token;

const confirmButtonElement = document.getElementById("confirm-button");
confirmButtonElement.addEventListener("click", handleConfirmButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleConfirmButtonClickEvent() {
	confirmButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
		account_deletion_session_token: accountDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("confirm_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		confirmButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();
			deleteAccountDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_account_deletion_session_token") {
			deleteAccountDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			confirmButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		confirmButtonElement.disabled = false;
		return;
	}

	deleteAccountDeletionTokenCookie();
	deleteAuthSessionTokenCookie();

	window.location.href = "/";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
		account_deletion_session_token: accountDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionToken();
			deleteAccountDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_account_deletion_session_token") {
			deleteAccountDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deleteAccountDeletionTokenCookie();

	window.location.href = "/account";
}
