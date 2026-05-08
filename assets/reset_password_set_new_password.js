const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const passwordResetToken = pageDataJSONObject.password_reset_token;

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
		password_reset_token: passwordResetToken,
		new_password: newPassword,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"set_password_reset_new_password",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_password_reset_token") {
			deletePasswordResetTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/reset-password";
			return;
		}
		if (actionResult.errorCode === "weak_password") {
			alert("This password is too weak. Please choose a stronger password.");
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

	deletePasswordResetTokenCookie();
	setSessionTokenCookie(actionResult.valuesJSONObject.session_token);

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent(event) {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_password_reset", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_password_reset_token") {
			deletePasswordResetTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/reset-password";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deletePasswordResetTokenCookie();

	window.location.href = "/reset-password";
}
