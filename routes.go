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

	if actionName == actionCreateSignup {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		signupToken, errorCode := server.createSignupAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCreateSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCreateSignup)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("signup_token", signupToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionDeleteSignup {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.deleteSignupAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeleteSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeleteSignup)

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

	if actionName == actionDeleteSession {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.deleteSessionAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeleteSession, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeleteSession)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionDeleteAllSessions {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.deleteAllSessionsAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeleteAllSessions, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeleteAllSessions)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionCreatePasswordUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordUpdateToken, errorCode := server.createPasswordUpdateAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCreatePasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCreatePasswordUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_update_token", passwordUpdateToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionDeletePasswordUpdate {
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
		errorCode := server.deletePasswordUpdateAction(requestId, sessionToken, passwordUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeletePasswordUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeletePasswordUpdate)

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
		newSessionToken, errorCode := server.setPasswordUpdateNewPasswordAction(requestId, sessionToken, passwordUpdateToken, newPassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetPasswordUpdateNewPassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetPasswordUpdateNewPassword)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("new_session_token", newSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCreateEmailAddressUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, errorCode := server.createEmailAddressUpdateAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCreateEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCreateEmailAddressUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionDeleteEmailAddressUpdate {
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
		errorCode := server.deleteEmailAddressUpdateAction(requestId, sessionToken, emailAddressUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeleteEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeleteEmailAddressUpdate)

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

	if actionName == actionCreateAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, errorCode := server.createAccountDeletionAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCreateAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCreateAccountDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionDeleteAccountDeletion {
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
		errorCode := server.deleteAccountDeletionAction(requestId, sessionToken, accountDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeleteAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeleteAccountDeletion)

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

	if actionName == actionCreatePasswordReset {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passwordResetToken, errorCode := server.createPasswordResetAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCreatePasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCreatePasswordReset)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("password_reset_token", passwordResetToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionDeletePasswordReset {
		passwordResetToken, err := values.GetString("password_reset_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.deletePasswordResetAction(requestId, passwordResetToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionDeletePasswordReset, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionDeletePasswordReset)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasswordResetOneTimePassword {
		passwordResetToken, err := values.GetString("password_reset_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		oneTimePassword, err := values.GetString("one_time_password")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyPasswordResetOneTimePassword(requestId, passwordResetToken, oneTimePassword)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyPasswordResetOneTimePassword, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyPasswordResetOneTimePassword)

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
	if errors.Is(err, errUserNotFound) {
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

	pageHTML := createUpdatePasswordVerifyPasswordPageHTML(requestId, sessionToken, passwordUpdateToken)

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

	pageHTML := createUpdateEmailAddressVerifyPasswordPageHTML(requestId, sessionToken, emailAddressUpdateToken)

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

	pageHTML := createDeleteAccountVerifyPasswordPageHTML(requestId, sessionToken, accountDeletionToken)

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

func (server *serverStruct) resetPasswordVerifyOneTimePasswordPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
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
		server.setBlankPasswordResetTokenCookie(w)
		w.Header().Set("Location", "/reset-password/set-new-password")
		w.WriteHeader(303)
		return
	}

	// Get user only if the password reset is still valid.
	// Using getUser() can return the old email address if the email address was updated (and the password reset was invalidated)
	// after validateRequestPasswordResetToken() but before this call.
	// This is especially important because password reset can be handled by clients not authenticated as the user.
	user, err := server.getPasswordResetUser(passwordReset.id)
	if errors.Is(err, errPasswordResetNotFound) {
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

	pageHTML := createResetPasswordVerifyOneTimePasswordPageHTML(requestId, passwordResetToken, user)

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
		server.setBlankPasswordResetTokenCookie(w)
		w.Header().Set("Location", "/reset-password/verify-one-time-password")
		w.WriteHeader(303)
		return
	}

	// See resetPasswordVerifyOneTimePasswordPageRoute()
	user, err := server.getPasswordResetUser(passwordReset.id)
	if errors.Is(err, errPasswordResetNotFound) {
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

	pageHTML := createResetPasswordSetNewPasswordPageHTML(requestId, passwordResetToken, user)

	writePageHTMLResponse(w, 200, pageHTML)
}

func writePageHTMLResponse(w http.ResponseWriter, statusCode int, pageHTML string) {
	pageHTMLBytes := []byte(pageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(pageHTMLBytes)))
	w.WriteHeader(statusCode)
	w.Write(pageHTMLBytes)
}
