const signInFormElement = document.getElementById("sign-in-form");
signInFormElement.addEventListener("submit", handleSignInFormSubmitEvent);

async function handleSignInFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("sign-in-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");
	const password = formData.get("password");
	const actionValuesJSONObject = {
		email_address: emailAddress,
		password: password,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("sign_in", actionValuesJSONObject);
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

	setSessionTokenCookie(actionResult.valuesJSONObject.session_token);

	window.location.href = "/sign-up/verify-email-address";
}
