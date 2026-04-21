package main

import (
	"errors"
	"fmt"
)

const (
	actionStartSignup                              = "start_signup"
	actionCancelSignup                             = "cancel_signup"
	actionSendSignupEmailAddressVerificationCode   = "send_signup_email_address_verification_code"
	actionVerifySignupEmailAddressVerificationCode = "verify_signup_email_address_verification_code"
	actionSetSignupPassword                        = "set_signup_password"

	actionSignIn = "sign_in"

	actionSignOut           = "sign_out"
	actionSignOutAllDevices = "sign_out_all_devices"

	actionStartPasswordUpdate              = "start_password_update"
	actionCancelPasswordUpdate             = "cancel_password_update"
	actionVerifyPasswordUpdateUserPassword = "verify_password_update_user_password"
	actionSetPasswordUpdateNewPassword     = "set_password_update_new_password"

	actionStartEmailAddressUpdate                                 = "start_email_address_update"
	actionCancelEmailAddressUpdate                                = "cancel_email_address_update"
	actionVerifyEmailAddressUpdateUserPassword                    = "verify_email_address_update_user_password"
	actionSetEmailAddressUpdateNewEmailAddress                    = "set_email_address_update_new_email_address"
	actionSendEmailAddressUpdateNewEmailAddressVerificationCode   = "send_email_address_update_new_email_address_verification_code"
	actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode = "verify_email_address_update_new_email_address_verification_code"

	actionStartAccountDeletion              = "start_account_deletion"
	actionCancelAccountDeletion             = "cancel_account_deletion"
	actionVerifyAccountDeletionUserPassword = "verify_account_deletion_user_password"
	actionConfirmAccountDeletion            = "confirm_account_deletion"

	actionStartPasswordReset          = "start_password_reset"
	actionCancelPasswordReset         = "cancel_password_reset"
	actionVerifyPasswordResetCode     = "verify_password_reset_code"
	actionSetPasswordResetNewPassword = "set_password_reset_new_password"
)

func (server *serverStruct) startSignupAction(requestId string, emailAddress string) (string, string) {
	const (
		errorCodeInvalidEmailAddress     = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeRateLimited             = "rate_limited"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	emailAddressValid := verifyAccountIdentifierEmailAddressPattern(emailAddress)
	if !emailAddressValid {
		return "", errorCodeInvalidEmailAddress
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.emailRateLimit.Consume(emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	signup, signupSecret, err := server.createSignup(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupStartedRequestEvent(requestId, signup.id, signup.emailAddress)

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	signupToken := createSignupToken(signup.id, signupSecret)

	return signupToken, ""
}

func (server *serverStruct) cancelSignupAction(requestId string, signupToken string) string {
	const (
		errorCodeInvalidSignupToken = "invalid_signup_token"
		errorCodeUnexpectedError    = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSignup(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendSignupEmailAddressVerificationCodeAction(requestId string, signupToken string) string {
	const (
		errorCodeInvalidSignupToken          = "invalid_signup_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if signup.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.emailRateLimit.Consume(signup.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifySignupEmailAddressVerificationCodeAction(requestId string, signupToken string, verificationCode string) string {
	const (
		errorCodeInvalidSignupToken          = "invalid_signup_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeIncorrectVerificationCode   = "incorrect_verification_code"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if signup.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(signup.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	emailAddressVerificationCodeValid := signup.compareEmailAddressVerificationCode(verificationCode)
	if !emailAddressVerificationCodeValid {
		server.logSignupEmailAddressVerificationFailedRequestEvent(requestId, signup.id, signup.emailAddress)
		return errorCodeIncorrectVerificationCode
	}

	err = server.setSignupAsEmailAddressVerified(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup as email address verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logSignupEmailAddressVerifiedRequestEvent(requestId, signup.id, signup.emailAddress)

	return ""
}

func (server *serverStruct) setSignupPasswordAction(requestId string, signupToken string, password string) (string, string) {
	const (
		errorCodeInvalidSignupToken      = "invalid_signup_token"
		errorCodeEmailAddressNotVerified = "email_address_not_verified"
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeInvalidPassword         = "invalid_password"
		errorCodeWeakPassword            = "weak_password"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return "", errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !signup.emailAddressVerified {
		return "", errorCodeEmailAddressNotVerified
	}

	if !verifyUserPasswordPattern(password) {
		return "", errorCodeInvalidPassword
	}

	passwordStrong, err := verifyUserPasswordStrength(password)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !passwordStrong {
		return "", errorCodeWeakPassword
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	user, session, sessionSecret, err := server.completeSignup(signup.id, password)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedRequestEvent(requestId, signup.id, signup.emailAddress, user.id, session.id)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) signInAction(requestId string, emailAddress string, password string) (string, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUserNotFound        = "user_not_found"
		errorCodeRateLimited         = "rate_limited"
		errorCodeIncorrectPassword   = "incorrect_password"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	emailAddressValid := verifyAccountIdentifierEmailAddressPattern(emailAddress)
	if !emailAddressValid {
		return "", errorCodeInvalidEmailAddress
	}

	user, err := server.getUserByEmailAddress(emailAddress)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeUserNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user by email address: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logSigninPasswordVerificationFailedRequestEvent(requestId, user.id)
		return "", errorCodeIncorrectPassword
	}

	session, sessionSecret, err := server.createSession(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignedInRequestEvent(requestId, user.id, session.id)

	err = server.sendSignedInEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, user.emailAddress, emailTypeSignedInNotification)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) signOutAction(requestId string, sessionToken string) string {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSession(session.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) signOutAllDevicesAction(requestId string, sessionToken string) string {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteUserSessions(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user sessions: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) startPasswordUpdateAction(requestId string, sessionToken string) (string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passwordUpdate, passwordUpdateSecret, err := server.createPasswordUpdate(session.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create password update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordUpdateStartedRequestEvent(requestId, session.id, session.userId, passwordUpdate.id)

	passwordUpdateToken := createPasswordUpdateToken(passwordUpdate.id, passwordUpdateSecret)

	return passwordUpdateToken, ""
}

func (server *serverStruct) cancelPasswordUpdateAction(requestId string, sessionToken string, passwordUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeSessionMismatch            = "session_mismatch"
		errorCodeUnexpectedError            = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdate, err := server.validatePasswordUpdateToken(passwordUpdateToken)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	err = server.deletePasswordUpdate(passwordUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete password update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyPasswordUpdateUserPasswordAction(requestId string, sessionToken string, passwordUpdateToken string, password string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken  = "invalid_password_update_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
		errorCodeIncorrectPassword           = "incorrect_password"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdate, err := server.validatePasswordUpdateToken(passwordUpdateToken)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if passwordUpdate.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logPasswordUpdateUserPasswordVerificationFailedRequestEvent(requestId, session.id, session.userId, passwordUpdate.id)
		return errorCodeIncorrectPassword
	}

	server.logPasswordUpdateUserPasswordVerifiedRequestEvent(requestId, session.id, session.userId, passwordUpdate.id)

	err = server.setPasswordUpdateAsUserIdentityVerified(passwordUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set password update as user identity verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasswordUpdateNewPasswordAction(requestId string, sessionToken string, passwordUpdateToken string, newPassword string) string {
	const (
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeSessionMismatch            = "session_mismatch"
		errorCodeUserIdentityNotVerified    = "user_identity_not_verified"
		errorCodeInvalidPassword            = "invalid_password"
		errorCodeWeakPassword               = "weak_password"
		errorCodeConflict                   = "conflict"
		errorCodeUnexpectedError            = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdate, err := server.validatePasswordUpdateToken(passwordUpdateToken)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !passwordUpdate.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !verifyUserPasswordPattern(newPassword) {
		return errorCodeInvalidPassword
	}

	newPasswordStrong, err := verifyUserPasswordStrength(newPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newPasswordStrong {
		return errorCodeWeakPassword
	}

	user, err := server.getUser(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.completePasswordUpdate(passwordUpdate.id, newPassword)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasswordUpdateCompletedRequestEvent(requestId, session.id, session.userId, passwordUpdate.id)

	err = server.sendPasswordUpdatedEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, user.emailAddress, emailTypePasswordUpdatedNotification)

	return ""
}

func (server *serverStruct) startEmailAddressUpdateAction(requestId string, sessionToken string) (string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	emailAddressUpdate, emailAddressUpdateSecret, err := server.createEmailAddressUpdate(session.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email address update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateStartedRequestEvent(requestId, session.id, session.userId, emailAddressUpdate.id)

	emailAddressUpdateToken := createEmailAddressUpdateToken(emailAddressUpdate.id, emailAddressUpdateSecret)

	return emailAddressUpdateToken, ""
}

func (server *serverStruct) cancelEmailAddressUpdateAction(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	err = server.deleteEmailAddressUpdate(emailAddressUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email address update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateUserPasswordAction(requestId string, sessionToken string, emailAddressUpdateToken string, password string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified    = "user_identity_already_verified"
		errorCodeIncorrectPassword              = "incorrect_password"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logEmailAddressUpdateUserPasswordVerificationFailedRequestEvent(requestId, session.id, session.userId, emailAddressUpdate.id)
		return errorCodeIncorrectPassword
	}

	server.logEmailAddressUpdateUserPasswordVerifiedRequestEvent(requestId, session.id, session.userId, emailAddressUpdate.id)

	err = server.setEmailAddressUpdateAsUserIdentityVerified(emailAddressUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update as user identity verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddressAction(requestId string, sessionToken string, emailAddressUpdateToken string, newEmailAddress string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressAlreadySet      = "new_email_address_already_set"
		errorCodeInvalidEmailAddress            = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressAlreadySet
	}

	if !verifyAccountIdentifierEmailAddressPattern(newEmailAddress) {
		return errorCodeInvalidEmailAddress
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.emailRateLimit.Consume(newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	newEmailAddressVerificationCode, err := server.setEmailAddressUpdateNewEmailAddress(emailAddressUpdate.id, newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update new email address: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(newEmailAddress, newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}
	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailRateLimit.Consume(emailAddressUpdate.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddressUpdate.newEmailAddress, emailAddressUpdate.newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, emailAddressUpdate.newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, sessionToken string, emailAddressUpdateToken string, verificationCode string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeIncorrectVerificationCode      = "incorrect_verification_code"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}

	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(emailAddressUpdate.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	verificationCodeCorrect := emailAddressUpdate.compareNewEmailAddressVerificationCode(verificationCode)
	if !verificationCodeCorrect {
		server.logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId, session.id, session.userId, emailAddressUpdate.id, emailAddressUpdate.newEmailAddress)
		return errorCodeIncorrectVerificationCode
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddressUpdate.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	oldUserEmailAddress, err := server.completeEmailAddressUpdate(emailAddressUpdate.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateCompletedRequestEvent(requestId, session.id, session.userId, emailAddressUpdate.id, emailAddressUpdate.newEmailAddress)

	err = server.sendEmailAddressUpdatedEmail(oldUserEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, oldUserEmailAddress, emailTypeEmailAddressUpdatedNotification)

	return ""
}

func (server *serverStruct) startAccountDeletionAction(requestId string, sessionToken string) (string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	accountDeletion, accountDeletionSecret, err := server.createAccountDeletion(session.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create account deletion: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logAccountDeletionStartedRequestEvent(requestId, session.id, session.userId, accountDeletion.id)

	accountDeletionToken := createAccountDeletionToken(accountDeletion.id, accountDeletionSecret)

	return accountDeletionToken, ""
}

func (server *serverStruct) cancelAccountDeletionAction(requestId string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate account deletion token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	err = server.deleteAccountDeletion(accountDeletion.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete account deletion: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyAccountDeletionUserPasswordAction(requestId string, sessionToken string, accountDeletionToken string, password string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
		errorCodeIncorrectPassword           = "incorrect_password"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if accountDeletion.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logAccountDeletionUserPasswordVerificationFailedRequestEvent(requestId, session.id, session.userId, accountDeletion.id)
		return errorCodeIncorrectPassword
	}

	err = server.setAccountDeletionAsUserIdentityVerified(accountDeletion.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set account deletion as user identity verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionUserPasswordVerifiedRequestEvent(requestId, session.id, session.userId, accountDeletion.id)

	return ""
}

func (server *serverStruct) confirmAccountDeletionAction(requestId string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityNotVerified     = "user_identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !accountDeletion.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	err = server.completeAccountDeletion(accountDeletion.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete account deletion: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionCompletedRequestEvent(requestId, session.id, session.userId, accountDeletion.id)

	return ""
}

func (server *serverStruct) startPasswordResetAction(requestId string, emailAddress string) (string, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUserNotFound        = "user_not_found"
		errorCodeRateLimited         = "rate_limited"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	if !verifyAccountIdentifierEmailAddressPattern(emailAddress) {
		return "", errorCodeInvalidEmailAddress
	}

	user, err := server.getUserByEmailAddress(emailAddress)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeUserNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user by email address: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailRateLimit.Consume(user.emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	passwordReset, passwordResetSecret, passwordResetVerificationCode, err := server.createPasswordReset(user.id, user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create password reset: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordResetStartedRequestEvent(requestId, passwordReset.id, passwordReset.userId, user.emailAddress)

	err = server.sendPasswordResetCodeEmail(user.emailAddress, passwordResetVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password reset verification email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, user.emailAddress, emailTypePasswordResetCode)

	passwordResetToken := createPasswordResetToken(passwordReset.id, passwordResetSecret)

	return passwordResetToken, ""
}

func (server *serverStruct) cancelPasswordResetAction(requestId string, passwordResetToken string) string {
	const (
		errorCodeInvalidPasswordResetToken = "invalid_password_reset_token"
		errorCodeUnexpectedError           = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deletePasswordReset(passwordReset.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete password reset: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyPasswordResetCode(requestId string, passwordResetToken string, code string) string {
	const (
		errorCodeInvalidPasswordResetToken  = "invalid_password_reset_token"
		errorCodeFirstFactorAlreadyVerified = "first_factor_already_verified"
		errorCodeIncorrectCode              = "incorrect_code"
		errorCodeRateLimited                = "rate_limited"
		errorCodeConflict                   = "conflict"
		errorCodeUnexpectedError            = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordReset.firstFactorVerified {
		return errorCodeFirstFactorAlreadyVerified
	}

	rateLimitAllowed := server.userPasswordResetCodeVerificationRateLimit.Consume(passwordReset.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	codeHash := server.hashPasswordResetCode(code, passwordReset.codeSalt)
	codeCorrect := constantTimeCompare(passwordReset.codeHash, codeHash)
	if !codeCorrect {
		server.logPasswordResetCodeVerificationFailedRequestEvent(requestId, passwordReset.id, passwordReset.userId, passwordReset.emailAddress)
		return errorCodeIncorrectCode
	}

	server.logPasswordResetCodeVerificationFailedRequestEvent(requestId, passwordReset.id, passwordReset.userId, passwordReset.emailAddress)

	err = server.setPasswordResetAsFirstFactorVerified(passwordReset.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set password reset as first factor verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasswordResetNewPasswordAction(requestId string, passwordResetToken string, newPassword string) (string, string) {
	const (
		errorCodeInvalidPasswordResetToken   = "invalid_password_reset_token"
		errorCodeVerificationCodeNotVerified = "verification_code_not_verified"
		errorCodeInvalidPassword             = "invalid_password"
		errorCodeWeakPassword                = "weak_password"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return "", errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !passwordReset.firstFactorVerified {
		return "", errorCodeVerificationCodeNotVerified
	}

	if !verifyUserPasswordPattern(newPassword) {
		return "", errorCodeInvalidPassword
	}

	newPasswordStrong, err := verifyUserPasswordStrength(newPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !newPasswordStrong {
		return "", errorCodeWeakPassword
	}

	user, err := server.getUser(passwordReset.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	session, sessionSecret, err := server.completePasswordReset(passwordReset.id, newPassword)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password reset: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordResetCompletedRequestEvent(requestId, passwordReset.id, passwordReset.userId, passwordReset.emailAddress, session.id)

	err = server.sendPasswordUpdatedEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, user.emailAddress, emailTypePasswordUpdatedNotification)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}
