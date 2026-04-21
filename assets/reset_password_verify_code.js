const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const passwordResetToken = pageDataJSONObject.password_reset_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "password_reset_updated") {
		window.location.reload();
	}
});

document.getElementById("verify-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const codeInputValue = formData.get("code");
	const code = codeInputValue.replaceAll(" ", "").replaceAll("-", "").toUpperCase();

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
		code: code,
	};
	const requestBodyJSONObject = {
		action: "verify_password_reset_code",
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
			if (resultJSONObject.error_code === "incorrect_code") {
				alert("Incorrect password reset code.");
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
