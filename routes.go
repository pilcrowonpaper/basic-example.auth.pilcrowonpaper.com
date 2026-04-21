package main

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/pilcrowonpaper/go-json"
)

func (server *serverStruct) actionRoute(w http.ResponseWriter, r *http.Request, requestId string) {
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
		signupToken, errorCode := server.startSignupAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartSignup)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("signup_token", signupToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelSignup {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelSignupAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelSignup)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendSignupEmailAddressVerificationCode {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendSignupEmailAddressVerificationCodeAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSendSignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSendSignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifySignupEmailAddressVerificationCode {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifySignupEmailAddressVerificationCodeAction(requestId, signupToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifySignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifySignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetSignupPassword {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.setSignupPasswordAction(requestId, signupToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetSignupPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetSignupPassword)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
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
		sessionToken, errorCode := server.signInAction(requestId, emailAddress, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSignIn, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSignIn)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSignOut {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSignOut, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSignOut)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSignOutAllDevices {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAllDevicesAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSignOutAllDevices, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSignOutAllDevices)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasswordUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateToken, errorCode := server.startPasswordUpdateAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasswordUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_update_token", passwordUpdateToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasswordUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateToken, err := values.GetString("password_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasswordUpdateAction(requestId, sessionToken, passwordUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelPasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelPasswordUpdate)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasswordUpdateUserPassword {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateToken, err := values.GetString("password_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyPasswordUpdateUserPasswordAction(requestId, sessionToken, passwordUpdateToken, password)
		if errorCode != "" {
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyPasswordUpdateUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyPasswordUpdateUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasswordUpdateNewPassword {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateToken, err := values.GetString("password_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newPassword, err := values.GetString("new_password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setPasswordUpdateNewPasswordAction(requestId, sessionToken, passwordUpdateToken, newPassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetPasswordUpdateNewPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetPasswordUpdateNewPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartEmailAddressUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, errorCode := server.startEmailAddressUpdateAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartEmailAddressUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailAddressUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailAddressUpdateAction(requestId, sessionToken, emailAddressUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelEmailAddressUpdate)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateUserPassword {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateUserPasswordAction(requestId, sessionToken, emailAddressUpdateToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyEmailAddressUpdateUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyEmailAddressUpdateUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetEmailAddressUpdateNewEmailAddress {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newEmailAddress, err := values.GetString("new_email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setEmailAddressUpdateNewEmailAddressAction(requestId, sessionToken, emailAddressUpdateToken, newEmailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetEmailAddressUpdateNewEmailAddress, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetEmailAddressUpdateNewEmailAddress)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, sessionToken, emailAddressUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSendEmailAddressUpdateNewEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, sessionToken, emailAddressUpdateToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, errorCode := server.startAccountDeletionAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartAccountDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, err := values.GetString("account_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelAccountDeletionAction(requestId, sessionToken, accountDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelAccountDeletion)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyAccountDeletionUserPassword {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, err := values.GetString("account_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		password, err := values.GetString("password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyAccountDeletionUserPasswordAction(requestId, sessionToken, accountDeletionToken, password)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyAccountDeletionUserPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyAccountDeletionUserPassword)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, err := values.GetString("account_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmAccountDeletionAction(requestId, sessionToken, accountDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionConfirmAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionConfirmAccountDeletion)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasswordReset {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordResetToken, errorCode := server.startPasswordResetAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasswordReset)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_reset_token", passwordResetToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasswordReset {
		passwordResetToken, err := values.GetString("password_reset_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasswordResetAction(requestId, passwordResetToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelPasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelPasswordReset)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasswordResetCode {
		passwordResetToken, err := values.GetString("password_reset_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		code, err := values.GetString("code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyPasswordResetCode(requestId, passwordResetToken, code)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyPasswordResetCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyPasswordResetCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasswordResetNewPassword {
		passwordResetToken, err := values.GetString("password_reset_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newPassword, err := values.GetString("new_password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.setPasswordResetNewPasswordAction(requestId, passwordResetToken, newPassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetPasswordResetNewPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetPasswordResetNewPassword)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
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

	w.WriteHeader(200)

	w.Write(bodyJSONBytes)
}

func (server *serverStruct) homePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createHomePageHTML(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) accountPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createAccountPageHTML(requestId, sessionToken, user)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createSignUpPageHTML(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpVerifyEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupToken, err := server.validateRequestSignupToken(r)
	if errors.Is(err, errInvalidSignupToken) {
		server.setBlankSignupTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/set-password")
		w.WriteHeader(303)
		return
	}

	pageHTML := createSignUpVerifyEmailAddressPageHTML(requestId, signupToken, signup)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpSetPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupToken, err := server.validateRequestSignupToken(r)
	if errors.Is(err, errInvalidSignupToken) {
		server.setBlankSignupTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	pageHTML := createSignUpSetPasswordPageHTML(requestId, signupToken, signup)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signInPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createSignInPage(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updatePasswordVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passwordUpdate, passwordUpdateToken, err := server.validateRequestPasswordUpdateToken(r)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		server.setBlankPasswordUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordUpdate.sessionId != session.id {
		server.setBlankPasswordUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if passwordUpdate.userIdentityVerified {
		w.Header().Set("Location", "/update-password/set-new-password")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		server.setBlankPasswordUpdateTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createUpdatePasswordVerifyPasswordPageHTML(requestId, sessionToken, passwordUpdateToken, user)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updatePasswordSetNewPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passwordUpdate, passwordUpdateToken, err := server.validateRequestPasswordUpdateToken(r)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		server.setBlankPasswordUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordUpdate.sessionId != session.id {
		server.setBlankPasswordUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !passwordUpdate.userIdentityVerified {
		w.Header().Set("Location", "/update-password/verify-password")
		w.WriteHeader(303)
		return
	}

	pageHTML := createUpdatePasswordSetNewPasswordPageHTML(requestId, sessionToken, passwordUpdateToken)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updateEmailAddressVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdate, emailAddressUpdateToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdate.sessionId != session.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if emailAddressUpdate.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/set-new-email-address")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createUpdateEmailAddressVerifyPasswordPageHTML(requestId, sessionToken, emailAddressUpdateToken, user)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updateEmailAddressSetNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdate, emailAddressUpdateToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdate.sessionId != session.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdate.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/verify-user-password")
		w.WriteHeader(303)
		return
	}
	if emailAddressUpdate.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/verify-new-email-address")
		w.WriteHeader(303)
		return
	}

	pageHTML := createUpdateEmailAddressSetNewEmailAddressPageHTML(requestId, sessionToken, emailAddressUpdateToken)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updateEmailAddressVerifyNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdate, emailAddressUpdateToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdate.sessionId != session.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdate.userIdentityVerified {
		w.Header().Set("Location", "/update-email-address/verify-user-password")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdate.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/set-new-email-address")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "news email address verification code not defined"
		server.logActionError(requestId, errorMessage)
		server.setBlankEmailAddressUpdateTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createUpdateEmailAddressVerifyNewEmailAddressPageHTML(requestId, sessionToken, emailAddressUpdateToken, emailAddressUpdate)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) deleteAccountVerifyPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletion, accountDeletionToken, err := server.validateRequestAccountDeletionToken(r)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletion.sessionId != session.id {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if accountDeletion.userIdentityVerified {
		w.Header().Set("Location", "/delete-account/confirm")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createDeleteAccountVerifyPasswordPageHTML(requestId, sessionToken, accountDeletionToken, user)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) deleteAccountConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletion, accountDeletionToken, err := server.validateRequestAccountDeletionToken(r)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletion.sessionId != session.id {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !accountDeletion.userIdentityVerified {
		w.Header().Set("Location", "/delete-account/verify-password")
		w.WriteHeader(303)
		return
	}

	pageHTML := createDeleteAccountConfirmPageHTML(requestId, sessionToken, accountDeletionToken)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) resetPasswordPageRoute(w http.ResponseWriter, _ *http.Request, requestId string) {
	pageHTML := createResetPasswordPageHTML(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) resetPasswordVerifyCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	passwordReset, passwordResetToken, err := server.validateRequestPasswordResetToken(r)
	if errors.Is(err, errInvalidPasswordResetToken) {
		server.setBlankPasswordResetTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password reset token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passwordReset.firstFactorVerified {
		w.Header().Set("Location", "/reset-password/set-new-password")
		w.WriteHeader(303)
		return
	}

	pageHTML := createResetPasswordVerifyCodePageHTML(requestId, passwordResetToken, passwordReset.emailAddress)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) resetPasswordSetNewPasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	passwordReset, passwordResetToken, err := server.validateRequestPasswordResetToken(r)
	if errors.Is(err, errInvalidPasswordResetToken) {
		server.setBlankPasswordResetTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request password reset token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !passwordReset.firstFactorVerified {
		w.Header().Set("Location", "/reset-password/verify-code")
		w.WriteHeader(303)
		return
	}

	user, err := server.getUser(passwordReset.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankPasswordResetTokenCookie(w)
		w.Header().Set("Location", "/reset-password")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createResetPasswordSetNewPasswordPageHTML(requestId, passwordResetToken, user.emailAddress)

	writePageHTMLResponse(w, 200, pageHTML)
}

func writePageHTMLResponse(w http.ResponseWriter, statusCode int, pageHTML string) {
	pageHTMLBytes := []byte(pageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(pageHTMLBytes)))
	w.WriteHeader(statusCode)
	w.Write(pageHTMLBytes)
}
