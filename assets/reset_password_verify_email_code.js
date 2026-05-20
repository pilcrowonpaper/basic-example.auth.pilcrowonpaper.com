const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const passwordResetSessionToken = pageDataJSONObject.password_reset_session_token;

const verifyEmailCodeFormElement = document.getElementById("verify-email-code-form");
verifyEmailCodeFormElement.addEventListener("submit", handleVerifyEmailCodeFormSubmitEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleVerifyEmailCodeFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailCodeInputValue = formData.get("email_code");
	const emailCode = emailCodeInputValue.replaceAll(" ", "").replaceAll("-", "").toUpperCase();

	const actionValuesJSONObject = {
		password_reset_session_token: passwordResetSessionToken,
		email_code: emailCode,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_password_reset_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_password_reset_session_token") {
			deletePasswordResetTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/reset-password";
			return;
		}
		if (actionResult.errorCode === "incorrect_email_code") {
			alert("Incorrect email code.");
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

	window.location.href = "/reset-password/set-new-password";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		password_reset_session_token: passwordResetSessionToken,
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
		if (actionResult.errorCode === "invalid_password_reset_session_token") {
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
