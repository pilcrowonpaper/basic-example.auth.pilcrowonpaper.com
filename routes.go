package main

import (
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/pilcrowonpaper/go-json"

	_ "embed"
)

const (
	routeHomePage                                    = "home_page"
	routeAccountPage                                 = "account_page"
	routeSignUpPage                                  = "sign_up_page"
	routeSignUpVerifyEmailAddressPage                = "sign_up_verify_email_address_page"
	routeSignUpSetPasswordPage                       = "sign_up_set_password_page"
	routeSignInPage                                  = "sign_in_page"
	routeUpdatePasswordVerifyPasswordPage            = "update_password_verify_password_page"
	routeUpdatePasswordSetNewPasswordPage            = "update_password_set_new_password_page"
	routeUpdateEmailAddressVerifyPasswordPage        = "update_email_address_verify_password_page"
	routeUpdateEmailAddressSetNewEmailAddressPage    = "update_email_address_set_new_email_address_page"
	routeUpdateEmailAddressVerifyNewEmailAddressPage = "update_email_address_verify_new_email_address_page"
	routeDeleteAccountVerifyPasswordPage             = "delete_account_verify_password_page"
	routeDeleteAccountConfirmPage                    = "delete_account_confirm_page"
	routeResetPasswordVerifyEmailCodePage            = "reset_password_verify_email_code_page"
	routeResetPasswordSetNewPasswordPage             = "reset_password_set_new_password_page"
)

func (server *serverStruct) actionRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	if secFetchSite != "same-origin" {
		w.WriteHeader(403)
		return
	}

	contentTypeHeader := r.Header.Get("Content-Type")
	if contentTypeHeader != "" {
		mediaType, mediaTypeParameters, err := mime.ParseMediaType(contentTypeHeader)
		if err != nil {
			w.WriteHeader(415)
			return
		}
		if mediaType != "application/json" {
			w.WriteHeader(415)
			return
		}
		charsetParameter, ok := mediaTypeParameters["charset"]
		if ok && strings.ToLower(charsetParameter) != "utf-8" {
			w.WriteHeader(415)
			return
		}
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	bodyJSONObject, err := json.ParseObject(string(bodyBytes))
	if err != nil {
		w.WriteHeader(400)
		return
	}

	actionName, err := bodyJSONObject.GetString("action")
	if err != nil {
		w.WriteHeader(400)
		return
	}
	values, err := bodyJSONObject.GetJSONObject("values")
	if err != nil {
		w.WriteHeader(400)
		return
	}

	if actionName == actionStartSignup {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		signupAuthSessionToken, errorCode := server.startSignupAction(requestId, clientIPAddress, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartSignup)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("signup_session_token", signupAuthSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelSignup {
		signupAuthSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelSignupAction(requestId, clientIPAddress, signupAuthSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelSignup)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendSignupEmailAddressVerificationCode {
		signupAuthSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendSignupEmailAddressVerificationCodeAction(requestId, clientIPAddress, signupAuthSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifySignupEmailAddressVerificationCode {
		signupAuthSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifySignupEmailAddressVerificationCodeAction(requestId, clientIPAddress, signupAuthSessionToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetSignupPassword {
		signupAuthSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.setSignupPasswordAction(requestId, clientIPAddress, signupAuthSessionToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetSignupPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetSignupPassword)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSignIn {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.signInAction(requestId, clientIPAddress, emailAddress, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSignIn, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSignIn)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSignOut {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAction(requestId, clientIPAddress, authSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSignOut, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSignOut)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSignOutAllDevices {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAllDevicesAction(requestId, clientIPAddress, authSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSignOutAllDevices, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSignOutAllDevices)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasswordUpdate {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateSessionToken, errorCode := server.startPasswordUpdateSessionAction(requestId, clientIPAddress, authSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasswordUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_update_session_token", passwordUpdateSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasswordUpdate {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateSessionToken, err := values.GetString("password_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasswordUpdateSessionAction(requestId, clientIPAddress, authSessionToken, passwordUpdateSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelPasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelPasswordUpdate)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasswordUpdateUserPassword {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateSessionToken, err := values.GetString("password_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyPasswordUpdateSessionUserPasswordAction(requestId, clientIPAddress, authSessionToken, passwordUpdateSessionToken, password)
		if errorCode != "" {
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasswordUpdateNewPassword {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateSessionToken, err := values.GetString("password_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newPassword, err := values.GetString("new_password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setPasswordUpdateSessionNewPasswordAction(requestId, clientIPAddress, authSessionToken, passwordUpdateSessionToken, newPassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartEmailAddressUpdate {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, errorCode := server.startEmailAddressUpdateAction(requestId, clientIPAddress, authSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartEmailAddressUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailAddressUpdate {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailAddressUpdateAction(requestId, clientIPAddress, authSessionToken, emailAddressUpdateSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelEmailAddressUpdate)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateUserPassword {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateUserPasswordAction(requestId, clientIPAddress, authSessionToken, emailAddressUpdateSessionToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetEmailAddressUpdateNewEmailAddress {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newEmailAddress, err := values.GetString("new_email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setEmailAddressUpdateNewEmailAddressAction(requestId, clientIPAddress, authSessionToken, emailAddressUpdateSessionToken, newEmailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendEmailAddressUpdateNewEmailAddressVerificationCode {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, clientIPAddress, authSessionToken, emailAddressUpdateSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, clientIPAddress, authSessionToken, emailAddressUpdateSessionToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartAccountDeletion {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, errorCode := server.startAccountDeletionAction(requestId, clientIPAddress, authSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartAccountDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("account_deletion_session_token", accountDeletionSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelAccountDeletion {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, err := values.GetString("account_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelAccountDeletionAction(requestId, clientIPAddress, authSessionToken, accountDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelAccountDeletion)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyAccountDeletionUserPassword {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, err := values.GetString("account_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyAccountDeletionUserPasswordAction(requestId, clientIPAddress, authSessionToken, accountDeletionSessionToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmAccountDeletion {
		authSessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, err := values.GetString("account_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmAccountDeletionAction(requestId, clientIPAddress, authSessionToken, accountDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionConfirmAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionConfirmAccountDeletion)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasswordReset {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordResetSessionToken, errorCode := server.startPasswordResetAction(requestId, clientIPAddress, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasswordReset)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_reset_session_token", passwordResetSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasswordReset {
		passwordResetSessionToken, err := values.GetString("password_reset_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasswordResetAction(requestId, clientIPAddress, passwordResetSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelPasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelPasswordReset)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendPasswordResetEmailCode {
		passwordResetSessionToken, err := values.GetString("password_reset_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendPasswordResetEmailCodeAction(requestId, clientIPAddress, passwordResetSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelPasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelPasswordReset)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasswordResetEmailCode {
		passwordResetSessionToken, err := values.GetString("password_reset_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailCode, err := values.GetString("email_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyPasswordResetEmailCodeAction(requestId, clientIPAddress, passwordResetSessionToken, emailCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyPasswordResetEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyPasswordResetEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasswordResetNewPassword {
		passwordResetSessionToken, err := values.GetString("password_reset_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newPassword, err := values.GetString("new_password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.setPasswordResetNewPasswordAction(requestId, clientIPAddress, passwordResetSessionToken, newPassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetPasswordResetNewPassword)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	w.WriteHeader(400)
}

func writeActionErrorResult(w http.ResponseWriter, requestId string, errorCode string) {
	bodyJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
	bodyJSONBuilder.AddBool("ok", false)
	bodyJSONBuilder.AddString("request_id", requestId)
	bodyJSONBuilder.AddString("error_code", errorCode)
	bodyJSON := bodyJSONBuilder.Done()
	bodyJSONBytes := []byte(bodyJSON)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(bodyJSONBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	w.WriteHeader(200)

	w.Write(bodyJSONBytes)
}

func writeActionSuccessResult(w http.ResponseWriter, requestId string, valuesJSON string) {
	bodyJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
	bodyJSONBuilder.AddBool("ok", true)
	bodyJSONBuilder.AddString("request_id", requestId)
	bodyJSONBuilder.AddJSON("values", valuesJSON)
	bodyJSON := bodyJSONBuilder.Done()
	bodyJSONBytes := []byte(bodyJSON)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(bodyJSONBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	w.WriteHeader(200)

	w.Write(bodyJSONBytes)
}

//go:embed assets/home.css
var homePageStylesheet string

func (server *serverStruct) homePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeHomePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Basic auth example"
	bodyHTML := `<h1>Basic auth example</h1>
<p>This an example website that implements email address and password authentication following best practices.
All accounts older than 24 hours are automatically deleted at midnight (UTC).</p>
<div id="auth">
	<a href="/sign-in" class="block-button">Sign in</a>
	<a href="/sign-up" class="block-button">Create an account</a>
</div>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, "", homePageStylesheet, "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/account.js
var accountPageScript string

//go:embed assets/account.css
var accountPageStylesheet string

func (server *serverStruct) accountPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeAccountPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeAccountPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "My account | Basic auth example"
	bodyHTMLTemplate := `<h1>My account</h1>
<section>
	<h2>Account information</h2>
	<p id="account-info-user-id">User ID: %s</p>
	<p id="account-info-email-address">Email address: %s</p>
	<button id="update-email-address-button" class="block-button">Update email address</button>
</section>
<section>
	<h2>Update password</h2>
	<button id="update-password-button" class="block-button">Update password</button>
</section>
<section>
	<h2>Sign out</h2>
	<div id="sign-out-controls">
		<button id="sign-out-button" class="block-button">Sign out</button>
		<button id="sign-out-all-devices-button" class="link-button">Sign out of all devices</button>
	</div>
</section>
<section>
	<h2>Delete your account</h2>
	<p id="delete-account-description">Deleting your account will permanently remove all your data. Some logs (including your IP address and email address) may be retained for up to 90 days.</p>
	<button id="delete-account-button" class="block-button">Delete account</button>
</section>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.id), html.EscapeString(user.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, accountPageScript, accountPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/sign_up.js
var signUpPageScript string

//go:embed assets/sign_up.css
var signUpPageStylesheet string

func (server *serverStruct) signUpPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Create an account | Basic auth example"
	bodyHTML := `<h1>Create an account</h1>
<p>All accounts older than 24 hours are permanently deleted at midnight UTC each day.
For security purposes, logs (which may include your IP address and email address) are retained for up to 90 days.
These logs are processed and stored by <a href="https://cloudflare.com">Cloudflare</a> and <a href="https://railway.com">Railway</a>.
We do not share or sell this data to any third parties.</p>
<p>The email address must be lowercase and no more than 100 characters long.</p>
<form id="sign-up-form">
	<label for="sign-up-form-email-address-input">Email address</label>
	<input id="sign-up-form-email-address-input" name="email_address" type="email" required maxlength="100" />
	<button id="sign-up-form-submit-button">Continue</button>
</form>
<a id="sign-in-link" href="/sign-in" class="link-button">Sign in with an existing account</a>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpPageScript, signUpPageStylesheet, "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/sign_up_verify_email_address.js
var signUpVerifyEmailAddressPageScript string

//go:embed assets/sign_up_verify_email_address.css
var signUpVerifyEmailAddressPageStylesheet string

func (server *serverStruct) signUpVerifyEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpVerifyEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupAuthSessionToken, err := server.validateRequestSignupAuthSessionToken(r)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		server.setBlankSignupAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpVerifyEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/set-password")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Verify your email address | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" required />
	<button id="verify-verification-code-form-submit-button">Verify email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signup.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("signup_session_token", signupAuthSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpVerifyEmailAddressPageScript, signUpVerifyEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/sign_up_set_password.js
var signUpSetPasswordPageScript string

//go:embed assets/sign_up_set_password.css
var signUpSetPasswordPageStylesheet string

func (server *serverStruct) signUpSetPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpSetPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupAuthSessionToken, err := server.validateRequestSignupAuthSessionToken(r)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		server.setBlankSignupAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpSetPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Set your password | Basic auth example"

	bodyHTMLTemplate := `<h1>Set your password</h1>
	<p>Use a strong password between 10 and 100 characters long. It must only include standard characters and cannot begin or end with a space.</p>
<form id="set-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden/>
	<label for="set-password-form-password-input">Password</label>
	<input id="set-password-form-password-input" name="password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-password-form-submit-button">Create account</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signup.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("signup_session_token", signupAuthSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpSetPasswordPageScript, signUpSetPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/sign_in.js
var signInPageScript string

//go:embed assets/sign_in.css
var signInPageStylesheet string

func (server *serverStruct) signInPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Sign in | Basic auth example"

	bodyHTML := `<h1>Sign in</h1>
<form id="sign-in-form">
	<label for="sign-in-form-email-address-input">Email address (lowercase)</label>
	<input id="sign-in-form-email-address-input" name="email_address" type="email" autocomplete="username" required maxlength="100"/>
	<label for="sign-in-form-password-input">Password</label>
	<input id="sign-in-form-password-input" name="password" type="password" autocomplete="current-password" required/>
	<button id="sign-in-form-submit-button">Continue</button>
</form>
<div id="links">
	<a id="create-account-link" href="/sign-up" class="link-button">Create a new account</a>
	<a id="forgot-password-link" href="/reset-password" class="link-button">Forgot password</a>
</div>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signInPageScript, signInPageStylesheet, "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/update_password_verify_password.js
var updatePasswordVerifyPasswordPageScript string

//go:embed assets/update_password_verify_password.css
var updatePasswordVerifyPasswordPageStylesheet string

func (server *serverStruct) updatePasswordVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdatePasswordVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passwordUpdateSession, passwordUpdateSessionToken, err := server.validateRequestPasswordUpdateSessionToken(r)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		server.setBlankPasswordUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdatePasswordVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordUpdateSession.authSessionId != authSession.id {
		server.setBlankPasswordUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if passwordUpdateSession.userIdentityVerified {
		w.Header().Set("Location", "/update-password/set-new-password")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		server.setBlankPasswordUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdatePasswordVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your password | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden />
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("password_update_session_token", passwordUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updatePasswordVerifyPasswordPageScript, updatePasswordVerifyPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/update_password_set_new_password.js
var updatePasswordSetNewPasswordPageScript string

//go:embed assets/update_password_set_new_password.css
var updatePasswordSetNewPasswordPageStylesheet string

func (server *serverStruct) updatePasswordSetNewPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdatePasswordSetNewPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passwordUpdateSession, passwordUpdateSessionToken, err := server.validateRequestPasswordUpdateSessionToken(r)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		server.setBlankPasswordUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdatePasswordSetNewPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordUpdateSession.authSessionId != authSession.id {
		server.setBlankPasswordUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !passwordUpdateSession.userIdentityVerified {
		w.Header().Set("Location", "/update-password/verify-password")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Set your new password | Basic auth example"

	bodyHTML := `<h1>Set your new password</h1>
<p>Use a strong password between 10 and 100 characters long. It must only include standard characters and cannot begin or end with a space.</p>
<form id="set-new-password-form">
	<label for="set-new-password-form-password-input">New password</label>
	<input id="set-new-password-form-password-input" name="new_password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-new-password-form-submit-button">Update password</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("password_update_session_token", passwordUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updatePasswordSetNewPasswordPageScript, updatePasswordSetNewPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/update_email_address_verify_password.js
var updateEmailAddressVerifyPasswordPageScript string

//go:embed assets/update_email_address_verify_password.css
var updateEmailAddressVerifyPasswordPageStylesheet string

func (server *serverStruct) updateEmailAddressVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdateSession, emailAddressUpdateSessionToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if emailAddressUpdateSession.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/set-new-email-address")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your password | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden />
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updateEmailAddressVerifyPasswordPageScript, updateEmailAddressVerifyPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/update_email_address_set_new_email_address.js
var updateEmailAddressSetNewEmailAddressPageScript string

//go:embed assets/update_email_address_set_new_email_address.css
var updateEmailAddressSetNewEmailAddressPageStylesheet string

func (server *serverStruct) updateEmailAddressSetNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressSetNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdateSession, emailAddressUpdateSessionToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressSetNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdateSession.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/verify-user-password")
		w.WriteHeader(303)
		return
	}
	if emailAddressUpdateSession.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/verify-new-email-address")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Set your new email address | Basic auth example"

	bodyHTML := `<h1>Set your new email address</h1>
<p>The email address must be lowercase and no more than 100 characters long.</p>
<form id="set-new-email-address-form">
	<label for="set-new-email-address-form-new-email-address-input">New email address</label>
	<input id="set-new-email-address-form-new-email-address-input" name="new_email_address" type="email" autocomplete="username" required maxlength="100" />
	<button id="set-new-email-address-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updateEmailAddressSetNewEmailAddressPageScript, updateEmailAddressSetNewEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/update_email_address_verify_new_email_address.js
var updateEmailAddressVerifyNewEmailAddressPageScript string

//go:embed assets/update_email_address_verify_new_email_address.css
var updateEmailAddressVerifyNewEmailAddressPageStylesheet string

func (server *serverStruct) updateEmailAddressVerifyNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdateSession, emailAddressUpdateSessionToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdateSession.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/verify-user-password")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdateSession.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/set-new-email-address")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "news email address verification code not defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)
		server.setBlankEmailAddressUpdateTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your new email address | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your new email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" required />
	<button id="verify-verification-code-form-submit-button">Update email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(emailAddressUpdateSession.newEmailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updateEmailAddressVerifyNewEmailAddressPageScript, updateEmailAddressVerifyNewEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/delete_account_verify_password.js
var deleteAccountVerifyPasswordPageScript string

//go:embed assets/delete_account_verify_password.css
var deleteAccountVerifyPasswordPageStylesheet string

func (server *serverStruct) deleteAccountVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletionSession, accountDeletionSessionToken, err := server.validateRequestAccountDeletionSessionToken(r)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletionSession.authSessionId != authSession.id {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if accountDeletionSession.userIdentityVerified {
		w.Header().Set("Location", "/delete-account/confirm")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountVerifyPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your password | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify your password</h1>
<form id="verify-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden />
	<label for="verify-password-form-password-input">Password</label>
	<input id="verify-password-form-password-input" name="password" type="password" autocomplete="current-password" required />
	<button id="verify-password-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("account_deletion_session_token", accountDeletionSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, deleteAccountVerifyPasswordPageScript, deleteAccountVerifyPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/delete_account_confirm.js
var deleteAccountConfirmPageScript string

//go:embed assets/delete_account_confirm.css
var deleteAccountConfirmPageStylesheet string

func (server *serverStruct) deleteAccountConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletionSession, accountDeletionSessionToken, err := server.validateRequestAccountDeletionSessionToken(r)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletionSession.authSessionId != authSession.id {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !accountDeletionSession.userIdentityVerified {
		w.Header().Set("Location", "/delete-account/verify-password")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Delete your account | Basic auth example"

	bodyHTML := `<h1>Delete your account</h1>
<p>Are you sure you want to delete your account? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button" class="block-button">Delete my account</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("account_deletion_session_token", accountDeletionSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, deleteAccountConfirmPageScript, deleteAccountConfirmPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/reset_password.js
var resetPasswordPageScript string

func (server *serverStruct) resetPasswordPageRoute(w http.ResponseWriter, requestId string, clientIPAddress string) {
	pageTitle := "Reset your password | Basic auth example"

	bodyHTML := `<h1>Reset your password</h1>
<p>Enter your account email address and we'll email you a password reset code.</p>
<form id="reset-password-form">
	<label for="reset-password-form-email-address-input">Email address (lowercase)</label>
	<input id="reset-password-form-email-address-input" name="email_address" type="email" autocomplete="username" required maxlength="100" />
	<button id="reset-password-form-submit-button">Continue</button>
</form>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, resetPasswordPageScript, "", "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/reset_password_verify_email_code.js
var resetPasswordVerifyEmailCodePageScript string

//go:embed assets/reset_password_verify_email_code.css
var resetPasswordVerifyEmailCodePageStylesheet string

func (server *serverStruct) resetPasswordVerifyEmailCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	passwordResetSession, passwordResetSessionToken, err := server.validateRequestPasswordResetToken(r)
	if errors.Is(err, errInvalidPasswordResetToken) {
		server.setBlankPasswordResetSessonTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password reset session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeResetPasswordVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordResetSession.userIdentityVerified {
		w.Header().Set("Location", "/reset-password/set-new-password")
		w.WriteHeader(303)
		return
	}

	userEmailAddress, err := server.getPasswordResetUserEmailAddress(passwordResetSession.id)
	if errors.Is(err, errItemNotFound) {
		server.setBlankPasswordResetSessonTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset session user email address: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeResetPasswordVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify email code | Basic auth example"

	bodyHTMLTemplate := `<h1>Verify email code</h1>
<p>We sent an 8-digit code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-email-code-form">
	<label for="verify-email-code-form-code-input">Password reset code (hyphens and spaces are optional)</label>
	<input id="verify-email-code-form-code-input" name="email_code" autocomplete="none" required />
	<button id="verify-email-code-form-submit-button">Continue</button>
</form>
<div id="controls">
	<button id="resend-email-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(userEmailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("password_reset_session_token", passwordResetSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, resetPasswordVerifyEmailCodePageScript, resetPasswordVerifyEmailCodePageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed assets/reset_password_set_new_password.js
var resetPasswordSetNewPasswordPageScript string

//go:embed assets/reset_password_set_new_password.css
var resetPasswordSetNewPasswordPageStylesheet string

func (server *serverStruct) resetPasswordSetNewPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	passwordResetSession, passwordResetSessionToken, err := server.validateRequestPasswordResetToken(r)
	if errors.Is(err, errInvalidPasswordResetToken) {
		server.setBlankPasswordResetSessonTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password reset session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeResetPasswordSetNewPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !passwordResetSession.userIdentityVerified {
		w.Header().Set("Location", "/reset-password/verify-email-code")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(passwordResetSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankPasswordResetSessonTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset session user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeResetPasswordSetNewPasswordPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Set your new password | Basic auth example"

	bodyHTMLTemplate := `<h1>Set your new password</h1>
	<p>Use a strong password between 10 and 100 characters long. It must only include standard characters and cannot begin or end with a space.</p>
<form id="set-new-password-form">
	<input name="email_address" autocomplete="username" value="%s" hidden />
	<label for="set-new-password-form-new-password-input">New password</label>
	<input id="set-new-password-form-new-password-input" name="new_password" type="password" autocomplete="new-password" required minlength="10" />
	<button id="set-new-password-form-submit-button">Reset password</button>
</form>
<button id="cancel-button" class="link-button class="link-button"">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("password_reset_session_token", passwordResetSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, resetPasswordSetNewPasswordPageScript, resetPasswordSetNewPasswordPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

func writePageHTMLResponse(w http.ResponseWriter, statusCode int, pageHTML string) {
	pageHTMLBytes := []byte(pageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(pageHTMLBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(statusCode)
	w.Write(pageHTMLBytes)
}
