const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "signup_updated") {
		window.location.reload();
	}
});

document.getElementById("set-password-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const password = formData.get("password");

	const actionValuesJSONObject = {
		signup_token: signupToken,
		password: password,
	};
	const requestBodyJSONObject = {
		action: "set_signup_password",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let sessionToken;
	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_signup_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("signup_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-up";
				return;
			}
			if (resultJSONObject.error_code === "weak_password") {
				alert("This password is too weak. Please choose a stronger password.");
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

		sessionToken = resultJSONObject.values.session_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("signup_updated");
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/account";
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_signup",
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
			if (resultJSONObject.error_code === "invalid_signup_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("signup_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-up";
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
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("signup_updated");

	window.location.href = "/sign-up";
});
