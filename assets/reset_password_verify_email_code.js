const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const passwordResetToken = pageDataJSONObject.password_reset_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "password_reset_updated") {
		window.location.reload();
	}
});

document.getElementById("verify-email-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailCodeInputValue = formData.get("email_code");
	const emailCode = emailCodeInputValue.replaceAll(" ", "").replaceAll("-", "").toUpperCase();

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
		email_code: emailCode,
	};
	const requestBodyJSONObject = {
		action: "verify_password_reset_email_code",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_password_reset_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("password_reset_updated");

				alert("Your session has expired.");
				window.location.href = "/reset-password";
				return;
			}
			if (resultJSONObject.error_code === "incorrect_email_code") {
				alert("Incorrect email code.");
				submitButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				submitButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	clientStateEventChannel.postMessage("password_reset_updated");

	window.location.href = "/reset-password/set-new-password";
});

const resendEmailCodeButtonElement = document.getElementById("resend-email-code-button");

resendEmailCodeButtonElement.addEventListener("click", async () => {
	resendEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
	};
	const requestBodyJSONObject = {
		action: "send_password_reset_email_code",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_password_reset_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("password_reset_updated");

				alert("Your session has expired.");
				window.location.href = "/reset-password";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				resendEmailCodeButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendEmailCodeButtonElement.disabled = false;
		return;
	}

	alert("We've sent another email to your inbox.");
	resendEmailCodeButtonElement.disabled = false;
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_password_reset",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_password_reset_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("password_reset_updated");

				alert("Your session has expired.");
				window.location.href = "/reset-password";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("password_reset_updated");

	window.location.href = "/reset-password";
});
