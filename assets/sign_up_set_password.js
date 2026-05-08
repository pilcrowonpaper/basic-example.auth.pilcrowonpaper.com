const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupAuthSessionToken = pageDataJSONObject.signup_session_token;

const setPasswordFormElement = document.getElementById("set-password-form");
setPasswordFormElement.addEventListener("submit", handleSetPasswordFormSubmitEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleSetPasswordFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const password = formData.get("password");
	const actionValuesJSONObject = {
		signup_session_token: signupAuthSessionToken,
		password: password,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("set_signup_password", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_session_token") {
			deleteSignupAuthSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
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

	deleteSignupAuthSessionTokenCookie();
	setAuthSessionTokenCookie(actionResult.valuesJSONObject.auth_session_token);

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_session_token: signupAuthSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_signup", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_session_token") {
			deleteSignupAuthSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deleteSignupAuthSessionTokenCookie();

	window.location.href = "/sign-up";
}
