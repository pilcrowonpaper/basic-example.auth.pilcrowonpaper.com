const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated") {
		window.location.href = window.location.href;
	}
});

const updateEmailAddressButtonElement = document.getElementById("update-email-address-button");

updateEmailAddressButtonElement.addEventListener("click", async () => {
	updateEmailAddressButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "create_email_address_update",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				updateEmailAddressButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		if (window.location.protocol === "https:") {
			document.cookie = `email_address_update_token=${resultJSONObject.values.email_address_update_token}; Max-Age=2400; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `email_address_update_token=${resultJSONObject.values.email_address_update_token}; Max-Age=2400; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("email_address_update_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	clientStateEventChannel.postMessage("email_address_update_updated");
	updateEmailAddressButtonElement.disabled = false;
	window.location.href = "/update-email-address/verify-password";
});

const updatePasswordButtonElement = document.getElementById("update-password-button");

updatePasswordButtonElement.addEventListener("click", async () => {
	updatePasswordButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "create_password_update",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				updatePasswordButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		if (window.location.protocol === "https:") {
			document.cookie = `password_update_token=${resultJSONObject.values.password_update_token}; Max-Age=2400; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `password_update_token=${resultJSONObject.values.password_update_token}; Max-Age=2400; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("password_update_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updatePasswordButtonElement.disabled = false;
		return;
	}

	updatePasswordButtonElement.disabled = false;
	window.location.href = "/update-password/verify-password";
});

const signOutButtonElement = document.getElementById("sign-out-button");

signOutButtonElement.addEventListener("click", async () => {
	signOutButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "delete_session",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				signOutButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		if (window.location.protocol === "https:") {
			document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("session_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	signOutButtonElement.disabled = false;
	window.location.href = "/sign-in";
});

const signOutAllDevicesButtonElement = document.getElementById("sign-out-all-devices-button");

signOutAllDevicesButtonElement.addEventListener("click", async () => {
	const confirmed = confirm("Do you want to sign out of all devices?");
	if (!confirmed) {
		return;
	}

	signOutAllDevicesButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "delete_all_sessions",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				signOutAllDevicesButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		if (window.location.protocol === "https:") {
			document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("session_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	signOutAllDevicesButtonElement.disabled = false;
	window.location.href = "/sign-in";
});

const deleteAccountButton = document.getElementById("delete-account-button");

deleteAccountButton.addEventListener("click", async () => {
	deleteAccountButton.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "create_account_deletion",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				deleteAccountButton.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		if (window.location.protocol === "https:") {
			document.cookie = `account_deletion_token=${resultJSONObject.values.account_deletion_token}; Max-Age=2400; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `account_deletion_token=${resultJSONObject.values.account_deletion_token}; Max-Age=2400; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("account_deletion_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButton.disabled = false;
		return;
	}

	deleteAccountButton.disabled = false;
	window.location.href = "/delete-account/verify-password";
});
