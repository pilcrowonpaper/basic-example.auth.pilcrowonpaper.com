const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const passwordResetToken = pageDataJSONObject.password_reset_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "password_reset_updated") {
		window.location.href = window.location.href;
	}
});

document.getElementById("verify-one-time-password-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-one-time-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const oneTimePasswordInputValue = formData.get("one_time_password");
	const oneTimePassword = oneTimePasswordInputValue.replaceAll(" ", "").replaceAll("-", "").toUpperCase();

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
		one_time_password: oneTimePassword,
	};
	const requestBodyJSONObject = {
		action: "verify_password_reset_one_time_password",
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
				clientStateEventChannel.postMessage("password_reset_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/reset-password";
				return;
			}
			if (resultJSONObject.error_code === "incorrect_one_time_password") {
				alert("Incorrect one-time password.");
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

		clientStateEventChannel.postMessage("password_reset_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/reset-password/set-new-password";
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		password_reset_token: passwordResetToken,
	};
	const requestBodyJSONObject = {
		action: "delete_password_reset",
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
				clientStateEventChannel.postMessage("password_reset_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/reset-password";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		clientStateEventChannel.postMessage("password_reset_updated");
		if (window.location.protocol === "https:") {
			document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `password_reset_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	window.location.href = "/reset-password";
});
