const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.auth_session_token;
const emailAddressUpdateSessionToken = pageDataJSONObject.email_address_update_session_token;

const verifyPasswordFormElement = document.getElementById("verify-password-form");
verifyPasswordFormElement.addEventListener("submit", handleVerifyPasswordFormSubmitEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleVerifyPasswordFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const password = formData.get("password");

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
		email_address_update_session_token: emailAddressUpdateSessionToken,
		password: password,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_email_address_update_user_password",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionTokenCookie();
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_email_address_update_session_token") {
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "incorrect_password") {
			alert("Incorrect password.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			submitButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/update-email-address/set-new-email-address";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: sessionToken,
		email_address_update_session_token: emailAddressUpdateSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_email_address_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteAuthSessionTokenCookie();
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_email_address_update_session_token") {
			deleteEmailAddressUpdateTokenCookie();

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

	deleteEmailAddressUpdateTokenCookie();

	window.location.href = "/account";
}
