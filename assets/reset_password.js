const clientStateEventChannel = new BroadcastChannel("client_state_event");

document.getElementById("reset-password-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("reset-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress,
	};
	const requestBodyJSONObject = {
		action: "create_password_reset",
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
			if (resultJSONObject.error_code === "invalid_email_address") {
				alert("Please enter a valid email address.");
				submitButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "user_not_found") {
				alert("No account found with this email address.");
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

		if (window.location.protocol === "https:") {
			document.cookie = `password_reset_token=${resultJSONObject.values.password_reset_token}; Max-Age=2400; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `password_reset_token=${resultJSONObject.values.password_reset_token}; Max-Age=2400; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("password_reset_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	submitButtonElement.disabled = false;
	window.location.href = "/reset-password/verify-one-time-password";
});
