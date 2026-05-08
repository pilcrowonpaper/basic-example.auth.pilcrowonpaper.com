const resetPasswordFormElement = document.getElementById("reset-password-form");
resetPasswordFormElement.addEventListener("submit", handleResetPasswordFormSubmitEvent);

async function handleResetPasswordFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("reset-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_password_reset", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_email_address") {
			alert("Please enter a valid email address.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "user_not_found") {
			alert("No account found with this email address.");
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

	setPasswordResetTokenCookie(actionResult.valuesJSONObject.password_reset_token);

	window.location.href = "/reset-password/verify-email-code";
}
