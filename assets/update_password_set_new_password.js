const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const SessionToken = pageDataJSONObject.auth_session_token;
const passwordUpdateSessionToken = pageDataJSONObject.password_update_session_token;

const setNewPasswordFormElement = document.getElementById("set-new-password-form");
setNewPasswordFormElement.addEventListener("submit", handleSetNewPasswordFormSubmitEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleSetNewPasswordFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-new-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const newPassword = formData.get("new_password");
	const actionValuesJSONObject = {
		auth_session_token: SessionToken,
		password_update_session_token: passwordUpdateSessionToken,
		new_password: newPassword,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"set_password_update_new_password",
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
			deletePasswordUpdateSessionTokenCookie();
			deleteAuthSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_password_update_session_token") {
			deletePasswordUpdateSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "weak_password") {
			alert("This password is too weak. Please choose a stronger password.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "invalid_password") {
			alert("Invalid password.");
			submitButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	deletePasswordUpdateSessionTokenCookie();

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: SessionToken,
		password_update_session_token: passwordUpdateSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_password_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deletePasswordUpdateSessionTokenCookie();
			deleteAuthSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "invalid_password_update_session_token") {
			deletePasswordUpdateSessionTokenCookie();

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

	deletePasswordUpdateSessionTokenCookie();

	window.location.href = "/account";
}
