const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const passwordUpdateToken = pageDataJSONObject.password_update_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "password_update_updated") {
		window.location.href = window.location.href;
	}
});

document.getElementById("set-new-password-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-new-password-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const newPassword = formData.get("new_password");

	const actionValuesJSONObject = {
		session_token: sessionToken,
		password_update_token: passwordUpdateToken,
		new_password: newPassword,
	};
	const requestBodyJSONObject = {
		action: "set_password_update_new_password",
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
			if (resultJSONObject.error_code === "invalid_session_token") {
				clientStateEventChannel.postMessage("session_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "invalid_password_update_token") {
				clientStateEventChannel.postMessage("password_update_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
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

		clientStateEventChannel.postMessage("password_update_updated");
		if (window.location.protocol === "https:") {
			document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
			document.cookie = `session_token=${resultJSONObject.values.new_session_token}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
			document.cookie = `session_token=${resultJSONObject.values.new_session_token}; Max-Age=86400; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("session_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/account";
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		password_update_token: passwordUpdateToken,
	};
	const requestBodyJSONObject = {
		action: "delete_password_update",
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
			if (resultJSONObject.error_code === "invalid_session_token") {
				clientStateEventChannel.postMessage("session_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "invalid_password_update_token") {
				clientStateEventChannel.postMessage("password_update_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		clientStateEventChannel.postMessage("password_update_updated");
		if (window.location.protocol === "https:") {
			document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `password_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	window.location.href = "/account";
});
