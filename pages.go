package main

import (
	"fmt"
	"html"

	"github.com/pilcrowonpaper/go-json"

	_ "embed"
)

//go:embed assets/home.css
var homePageStylesheet string

func createHomePageHTML(requestId string) string {
	title := "Basic auth example"
	bodyHTML := `<h1>Basic auth example</h1>
<p>This is a website that implements basic email address and password auth using best practices. It supports email address verification, password update, email address update, password reset, and account deletion. All accounts are automatically deleted at midnight (UTC).</p>
<div id="auth">
	<a href="/sign-in">Sign in</a>
	<a href="/sign-up">Create an account</a>
</div>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, "", homePageStylesheet, "")

	return pageHTML
}

//go:embed assets/account.js
var accountPageScript string

//go:embed assets/account.css
var accountPageStylesheet string

func createAccountPageHTML(requestId string, sessionToken string, user userStruct) string {
	title := "My account | Basic auth example"
	bodyHTMLTemplate := `<h1>My account</h1>
<section>
	<h2>Account information</h2>
	<p id="account-info-user-id">User ID: %s</p>
	<p id="account-info-email-address">Email address: %s</p>
</section>
<section>
	<h2>Update email address</h2>
	<button id="update-email-address-button">Update email address</button>
</section>
<section>
	<h2>Update password</h2>
	<p id="update-password-description">Updating your password will sign you out of all other devices..</p>
	<button id="update-password-button">Update password</button>
</section>
<section>
	<h2>Sign out</h2>
	<div id="sign-out-controls">
		<button id="sign-out-button">Sign out</button>
		<button id="sign-out-all-devices-button">Sign out of all devices</button>
	</div>
</section>
<section>
	<h2>Delete your account</h2>
	<p id="delete-account-description">Deleting your account will permanently remove all your data. Some logs (including your IP address and email address) may be retained for up to 90 days.</p>
	<button id="delete-account-button">Delete account</button>
</section>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.id), html.EscapeString(user.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, accountPageScript, accountPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/sign_up.js
var signUpPageScript string

//go:embed assets/sign_up.css
var signUpPageStylesheet string

func createSignUpPageHTML(requestId string) string {
	title := "Create an account | Basic auth example"
	bodyHTML := `<h1>Create an account</h1>
<p>All accounts are permanently deleted at midnight UTC each day. For security purposes, logs (which may include your IP address and email address) are retained for up to 90 days. These logs are processed and stored by <a href="https://cloudflare.com">Cloudflare</a> and <a href="https://railway.com">Railway</a>. We do not share or sell this data to any third parties.</p>
<form id="sign-up-form">
	<label for="sign-up-form-email-address-input">Email address</label>
	<input id="sign-up-form-email-address-input" name="email_address" type="email" required />
	<button id="sign-up-form-submit-button">Continue</button>
</form>
<a id="sign-in-link" href="/sign-in">Sign in with an existing account</a>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpPageScript, signUpPageStylesheet, "")

	return pageHTML
}

//go:embed assets/sign_up_verify_email_address.js
var signUpVerifyEmailAddressPageScript string

//go:embed assets/sign_up_verify_email_address.css
var signUpVerifyEmailAddressPageStylesheet string

func createSignUpVerifyEmailAddressPageHTML(requestId string, signupToken string, signup signupStruct) string {
	title := "Verify your email address | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" required />
	<button id="verify-verification-code-form-submit-button">Verify email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button">Resend verification code</button>
	<button id="cancel-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signup.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("signup_token", signupToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpVerifyEmailAddressPageScript, signUpVerifyEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/sign_up_set_password.js
var signUpSetPasswordPageScript string

//go:embed assets/sign_up_set_password.css
var signUpSetPasswordPageStylesheet string

func createSignUpSetPasswordPageHTML(requestId string, signupToken string, signup signupStruct) string {
	title := "Set your password | Basic auth example"

	bodyHTMLTemplate := `<h1>Set your password</h1>
<p>Use a strong password with at least 10 characters.</p>
<form id="set-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden/>
	<label for="set-password-form-password-input">Password</label>
	<input id="set-password-form-password-input" name="password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-password-form-submit-button">Create account</button>
</form>
<button id="cancel-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signup.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("signup_token", signupToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpSetPasswordPageScript, signUpSetPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/sign_in.js
var signInPageScript string

//go:embed assets/sign_in.css
var signInPageStylesheet string

func createSignInPage(requestId string) string {
	title := "Sign in | Basic auth example"

	bodyHTML := `<h1>Sign in</h1>
<form id="sign-in-form">
	<label for="sign-in-form-email-address-input">Email address</label>
	<input id="sign-in-form-email-address-input" name="email_address" type="email" autocomplete="username" required/>
	<label for="sign-in-form-password-input">Password</label>
	<input id="sign-in-form-password-input" name="password" type="password" autocomplete="current-password" required/>
	<button id="sign-in-form-submit-button">Continue</button>
</form>
<div id="links">
	<a id="create-account-link" href="/sign-up">Create a new account</a>
	<a id="forgot-password-link" href="/reset-password">Forgot password</a>
</div>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, signInPageScript, signInPageStylesheet, "")

	return pageHTML
}

//go:embed assets/update_password_verify_password.js
var updatePasswordVerifyPasswordPageScript string

//go:embed assets/update_password_verify_password.css
var updatePasswordVerifyPasswordPageStylesheet string

func createUpdatePasswordVerifyPasswordPageHTML(requestId string, sessionToken string, passwordUpdateToken string) string {
	title := "Verify your password | Basic auth example"

	bodyHTML := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("password_update_token", passwordUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updatePasswordVerifyPasswordPageScript, updatePasswordVerifyPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/update_password_set_new_password.js
var updatePasswordSetNewPasswordPageScript string

//go:embed assets/update_password_set_new_password.css
var updatePasswordSetNewPasswordPageStylesheet string

func createUpdatePasswordSetNewPasswordPageHTML(requestId string, sessionToken string, passwordUpdateToken string) string {
	title := "Set your new password | Basic auth example"

	bodyHTML := `<h1>Set your new password</h1>
<p>Use a strong password with at least 10 characters.</p>
<form id="set-new-password-form">
	<label for="set-new-password-form-password-input">New password</label>
	<input id="set-new-password-form-password-input" name="new_password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-new-password-form-submit-button">Update password</button>
</form>
<button id="cancel-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("password_update_token", passwordUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updatePasswordSetNewPasswordPageScript, updatePasswordSetNewPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/update_email_address_verify_password.js
var updateEmailAddressVerifyPasswordPageScript string

//go:embed assets/update_email_address_verify_password.css
var updateEmailAddressVerifyPasswordPageStylesheet string

func createUpdateEmailAddressVerifyPasswordPageHTML(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	title := "Verify your password | Basic auth example"

	bodyHTML := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updateEmailAddressVerifyPasswordPageScript, updateEmailAddressVerifyPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/update_email_address_set_new_email_address.js
var updateEmailAddressSetNewEmailAddressPageScript string

//go:embed assets/update_email_address_set_new_email_address.css
var updateEmailAddressSetNewEmailAddressPageStylesheet string

func createUpdateEmailAddressSetNewEmailAddressPageHTML(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	title := "Set your new email address | Basic auth example"

	bodyHTML := `<h1>Set your new email address</h1>
<form id="set-new-email-address-form">
	<label for="set-new-email-address-form-new-email-address-input">New email address</label>
	<input id="set-new-email-address-form-new-email-address-input" name="new_email_address" type="email" autocomplete="username" required />
	<button id="set-new-email-address-form-submit-button">Continue</button>
</form>
<button id="cancel-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updateEmailAddressSetNewEmailAddressPageScript, updateEmailAddressSetNewEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/update_email_address_verify_new_email_address.js
var updateEmailAddressVerifyNewEmailAddressPageScript string

//go:embed assets/update_email_address_verify_new_email_address.css
var updateEmailAddressVerifyNewEmailAddressPageStylesheet string

func createUpdateEmailAddressVerifyNewEmailAddressPageHTML(requestId string, sessionToken string, emailAddressUpdateToken string, emailAddressUpdate emailAddressUpdateStruct) string {
	title := "Verify your new email address | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your new email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" required />
	<button id="verify-verification-code-form-submit-button">Update email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button">Resend verification code</button>
	<button id="cancel-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(emailAddressUpdate.newEmailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updateEmailAddressVerifyNewEmailAddressPageScript, updateEmailAddressVerifyNewEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/delete_account_verify_password.js
var deleteAccountVerifyPasswordPageScript string

//go:embed assets/delete_account_verify_password.css
var deleteAccountVerifyPasswordPageStylesheet string

func createDeleteAccountVerifyPasswordPageHTML(requestId string, sessionToken string, accountDeletionToken string) string {
	title := "Verify your password | Basic auth example"

	bodyHTML := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, deleteAccountVerifyPasswordPageScript, deleteAccountVerifyPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/delete_account_confirm.js
var deleteAccountConfirmPageScript string

//go:embed assets/delete_account_confirm.css
var deleteAccountConfirmPageStylesheet string

func createDeleteAccountConfirmPageHTML(requestId string, sessionToken string, accountDeletionToken string) string {
	title := "Delete your account | Basic auth example"

	bodyHTML := `<h1>Delete your account</h1>
<p>Are you sure you want to delete your account? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button">Delete my account</button>
	<button id="cancel-button">Cancel</button>
</div>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, deleteAccountConfirmPageScript, deleteAccountConfirmPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/reset_password.js
var resetPasswordPageScript string

func createResetPasswordPageHTML(requestId string) string {
	title := "Reset your password | Basic auth example"

	bodyHTML := `<h1>Reset your password</h1>
<p>Enter your account's email address and we'll email you a one-time password to reset your password.</p>
<form id="reset-password-form">
	<label for="reset-password-form-email-address-input">Email address</label>
	<input id="reset-password-form-email-address-input" name="email_address" type="email" autocomplete="username" required />
	<button id="reset-password-form-submit-button">Continue</button>
</form>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, resetPasswordPageScript, "", "")

	return pageHTML
}

//go:embed assets/reset_password_verify_one_time_password.js
var resetPasswordVerifyOneTimePasswordPageScript string

//go:embed assets/reset_password_verify_one_time_password.css
var resetPasswordVerifyOneTimePasswordPageStylesheet string

func createResetPasswordVerifyOneTimePasswordPageHTML(requestId string, passwordResetToken string, user userStruct) string {
	title := "Verify one-time password | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify one-time password</h1>
<p>We sent an 8-digit one-time password to %s. Check your spam or junk folder if you don't see it.</p>
<form id="verify-one-time-password-form">
	<label for="verify-one-time-password-form-one-time-password-input">One time password</label>
	<input id="verify-one-time-password-form-one-time-password-input" name="one_time_password" autocomplete="none" required />
	<button id="verify-one-time-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("password_reset_token", passwordResetToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, resetPasswordVerifyOneTimePasswordPageScript, resetPasswordVerifyOneTimePasswordPageStylesheet, dataJSON)

	return pageHTML
}

func createUnexpectedErrorErrorPageHTML(requestId string) string {
	title := "An unexpected error occurred | Basic auth example"

	bodyHTML := `<h1>An unexpected error occurred</h1>
<p>Something went wrong. Please refresh the page or try again later.</p>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, "", "", "")

	return pageHTML
}

//go:embed assets/reset_password_set_new_password.js
var resetPasswordSetNewPasswordPageScript string

//go:embed assets/reset_password_set_new_password.css
var resetPasswordSetNewPasswordPageStylesheet string

func createResetPasswordSetNewPasswordPageHTML(requestId string, passwordResetToken string, user userStruct) string {
	title := "Set your new password | Basic auth example"

	bodyHTMLTemplate := `<h1>Set your new password</h1>
<p>Use a strong password with at least 10 characters.</p>
<form id="set-new-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden />
	<label for="set-new-password-form-new-password-input">One time password</label>
	<input id="set-new-password-form-new-password-input" name="new_password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-new-password-form-submit-button">Reset password</button>
</form>
<button id="cancel-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("password_reset_token", passwordResetToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, resetPasswordSetNewPasswordPageScript, resetPasswordSetNewPasswordPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed assets/base.css
var baseStylesheet string

func createPageHTML(requestId string, title string, bodyHTML string, script string, stylesheet string, dataJSON string) string {
	htmlTemplate := `<html lang="en">
<head>
	<title>%s</title>
	<meta name="description" content="A basic email address and password auth example." />

	<meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" />

	<meta property="og:title" content="%s" />
	<meta property="og:type" content="website" />
	<meta property="og:locale" content="en_US" />
	<meta property="og:site_name" content="Basic auth example" />
	<meta property="og:description" content="A basic email address and password auth example." />
	<meta property="og:url" content="https://basic-example.auth.pilcrowonpaper.com" />
	<meta property="og:image" content="https://pilcrowonpaper.com/profile.jpg" />

	<meta name="twitter:card" content="summary">
    <meta name="twitter:site" content="@pilcrowonpaper">

	<style>%s</style>
	<style>%s</style>
</head>

<body>
	<header>
		<a id="home-link" href="/">Basic auth example</a>
	</header>
	<main>%s</main>
	<footer>
		<p id="footer-request-id">Request ID: %s</p>
	</footer>
</body>
<script type="module">%s</script>
<script id="data" type="application/json">%s</script>
</html>`

	pageHTML := fmt.Sprintf(
		htmlTemplate,
		html.EscapeString(title),
		html.EscapeString(title),
		baseStylesheet,
		stylesheet,
		bodyHTML,
		html.EscapeString(requestId),
		script,
		dataJSON,
	)

	return pageHTML
}

var htmlSafeJSONStringCharacterEscapingBehavior json.StringCharacterEscapingBehaviorInterface = htmlSafeJSONStringCharacterEscapingBehaviorStruct{}

type htmlSafeJSONStringCharacterEscapingBehaviorStruct struct{}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseCharacter(r rune) bool {
	return r != '<' && r != '>'
}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseShorthandEscapeSequence(_ rune) bool {
	return true
}
