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

	actionStartPasswordReset           = "start_password_reset"
	actionCancelPasswordReset          = "cancel_password_reset"
	actionSendPasswordResetEmailCode   = "send_password_reset_email_code"
	actionVerifyPasswordResetEmailCode = "verify_password_reset_email_code"
	actionSetPasswordResetNewPassword  = "set_password_reset_new_password"
)

func (server *serverStruct) startSignupAction(requestId string, clientIPAddress string, emailAddress string) (string, string) {
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
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.emailRateLimit.Consume(emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	signup, signupSecret, err := server.createSignupSession(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupStartedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	signupAuthSessionToken := createSessionToken(signup.id, signupSecret)

	return signupAuthSessionToken, ""
}

func (server *serverStruct) cancelSignupAction(requestId string, clientIPAddress string, signupAuthSessionToken string) string {
	const (
		errorCodeInvalidSignupAuthSessionToken = "invalid_signup_session_token"
		errorCodeUnexpectedError               = "unexpected_error"
	)

	signup, err := server.validateSignupAuthSessionToken(signupAuthSessionToken)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		return errorCodeInvalidSignupAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSignupSession(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signup session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendSignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupAuthSessionToken string) string {
	const (
		errorCodeInvalidSignupAuthSessionToken = "invalid_signup_session_token"
		errorCodeEmailAddressAlreadyVerified   = "email_address_already_verified"
		errorCodeRateLimited                   = "rate_limited"
		errorCodeUnexpectedError               = "unexpected_error"
	)

	signup, err := server.validateSignupAuthSessionToken(signupAuthSessionToken)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		return errorCodeInvalidSignupAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
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
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifySignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupAuthSessionToken string, verificationCode string) string {
	const (
		errorCodeInvalidSignupAuthSessionToken = "invalid_signup_session_token"
		errorCodeEmailAddressAlreadyVerified   = "email_address_already_verified"
		errorCodeIncorrectVerificationCode     = "incorrect_verification_code"
		errorCodeRateLimited                   = "rate_limited"
		errorCodeUnexpectedError               = "unexpected_error"
	)

	signup, err := server.validateSignupAuthSessionToken(signupAuthSessionToken)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		return errorCodeInvalidSignupAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
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
		server.logSignupEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)
		return errorCodeIncorrectVerificationCode
	}

	err = server.setSignupSessionAsEmailAddressVerified(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup session as email address verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logSignupEmailAddressVerifiedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)

	return ""
}

func (server *serverStruct) setSignupPasswordAction(requestId string, clientIPAddress string, signupAuthSessionToken string, password string) (string, string) {
	const (
		errorCodeInvalidSignupAuthSessionToken = "invalid_signup_session_token"
		errorCodeEmailAddressNotVerified       = "email_address_not_verified"
		errorCodeEmailAddressAlreadyUsed       = "email_address_already_used"
		errorCodeInvalidPassword               = "invalid_password"
		errorCodeWeakPassword                  = "weak_password"
		errorCodeConflict                      = "conflict"
		errorCodeUnexpectedError               = "unexpected_error"
	)

	signup, err := server.validateSignupAuthSessionToken(signupAuthSessionToken)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		return "", errorCodeInvalidSignupAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPassword, errorMessage)
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
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !passwordStrong {
		return "", errorCodeWeakPassword
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	user, authSession, authSessionSecret, err := server.completeSignup(signup.id, password)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress, user.id, authSession.id)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}

func (server *serverStruct) signInAction(requestId string, clientIPAddress string, emailAddress string, password string) (string, string) {
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
		server.logActionInternalError(requestId, clientIPAddress, actionSignIn, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logSigninPasswordVerificationFailedRequestEvent(requestId, clientIPAddress, user.id)
		return "", errorCodeIncorrectPassword
	}

	authSession, authSessionSecret, err := server.createAuthSession(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignIn, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignedInRequestEvent(requestId, clientIPAddress, user.id, authSession.id)

	err = server.sendSignedInEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignIn, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypeSignedInNotification)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}

func (server *serverStruct) signOutAction(requestId string, clientIPAddress string, SessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteAuthSession(authSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete auth session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) signOutAllDevicesAction(requestId string, clientIPAddress string, SessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteUserAuthSessions(authSession.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user sessions: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) startPasswordUpdateSessionAction(requestId string, clientIPAddress string, SessionToken string) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasswordUpdate, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passwordUpdateSession, passwordUpdateSessionSecret, err := server.createPasswordUpdateSession(authSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create password update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasswordUpdate, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordUpdateStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passwordUpdateSession.id)

	passwordUpdateSessionToken := createSessionToken(passwordUpdateSession.id, passwordUpdateSessionSecret)

	return passwordUpdateSessionToken, ""
}

func (server *serverStruct) cancelPasswordUpdateSessionAction(requestId string, clientIPAddress string, SessionToken string, passwordUpdateSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken           = "invalid_auth_session_token"
		errorCodeInvalidPasswordUpdateSessionToken = "invalid_password_update_session_token"
		errorCodeSessionMismatch                   = "session_mismatch"
		errorCodeUnexpectedError                   = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasswordUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdateSession, err := server.validatePasswordUpdateSessionToken(passwordUpdateSessionToken)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasswordUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	err = server.deletePasswordUpdateSession(passwordUpdateSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete password update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasswordUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyPasswordUpdateSessionUserPasswordAction(requestId string, clientIPAddress string, SessionToken string, passwordUpdateSessionToken string, password string) string {
	const (
		errorCodeInvalidAuthSessionToken           = "invalid_auth_session_token"
		errorCodeInvalidPasswordUpdateSessionToken = "invalid_password_update_session_token"
		errorCodeSessionMismatch                   = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified       = "user_identity_already_verified"
		errorCodeIncorrectPassword                 = "incorrect_password"
		errorCodeRateLimited                       = "rate_limited"
		errorCodeUnexpectedError                   = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdateSession, err := server.validatePasswordUpdateSessionToken(passwordUpdateSessionToken)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if passwordUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logPasswordUpdateUserPasswordVerificationFailedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passwordUpdateSession.id)
		return errorCodeIncorrectPassword
	}

	server.logPasswordUpdateUserPasswordVerifiedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passwordUpdateSession.id)

	err = server.setPasswordUpdateSessionAsUserIdentityVerified(passwordUpdateSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set password update session as user identity verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasswordUpdateSessionNewPasswordAction(requestId string, clientIPAddress string, SessionToken string, passwordUpdateSessionToken string, newPassword string) string {
	const (
		errorCodeInvalidAuthSessionToken           = "invalid_auth_session_token"
		errorCodeInvalidPasswordUpdateSessionToken = "invalid_password_update_session_token"
		errorCodeSessionMismatch                   = "session_mismatch"
		errorCodeUserIdentityNotVerified           = "user_identity_not_verified"
		errorCodeInvalidPassword                   = "invalid_password"
		errorCodeWeakPassword                      = "weak_password"
		errorCodeConflict                          = "conflict"
		errorCodeUnexpectedError                   = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	passwordUpdateSession, err := server.validatePasswordUpdateSessionToken(passwordUpdateSessionToken)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !passwordUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !verifyUserPasswordPattern(newPassword) {
		return errorCodeInvalidPassword
	}

	newPasswordStrong, err := verifyUserPasswordStrength(newPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newPasswordStrong {
		return errorCodeWeakPassword
	}

	user, err := server.getUser(authSession.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.completePasswordUpdateSession(passwordUpdateSession.id, newPassword)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasswordUpdateCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passwordUpdateSession.id)

	err = server.sendPasswordUpdatedEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordUpdateNewPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasswordUpdatedNotification)

	return ""
}

func (server *serverStruct) startEmailAddressUpdateAction(requestId string, clientIPAddress string, SessionToken string) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return "", errorCodeUnexpectedError
	}

	emailAddressUpdateSession, emailAddressUpdateSessionSecret, err := server.createEmailAddressUpdate(authSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id)

	emailAddressUpdateSessionToken := createSessionToken(emailAddressUpdateSession.id, emailAddressUpdateSessionSecret)

	return emailAddressUpdateSessionToken, ""
}

func (server *serverStruct) cancelEmailAddressUpdateAction(requestId string, clientIPAddress string, SessionToken string, emailAddressUpdateSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken        = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	err = server.deleteEmailAddressUpdate(emailAddressUpdateSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateUserPasswordAction(requestId string, clientIPAddress string, SessionToken string, emailAddressUpdateSessionToken string, password string) string {
	const (
		errorCodeInvalidAuthSessionToken        = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified    = "user_identity_already_verified"
		errorCodeIncorrectPassword              = "incorrect_password"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if emailAddressUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logEmailAddressUpdateUserPasswordVerificationFailedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id)
		return errorCodeIncorrectPassword
	}

	server.logEmailAddressUpdateUserPasswordVerifiedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id)

	err = server.setEmailAddressUpdateAsUserIdentityVerified(emailAddressUpdateSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update session as user identity verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddressAction(requestId string, clientIPAddress string, SessionToken string, emailAddressUpdateSessionToken string, newEmailAddress string) string {
	const (
		errorCodeInvalidAuthSessionToken        = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressAlreadySet      = "new_email_address_already_set"
		errorCodeInvalidEmailAddress            = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if emailAddressUpdateSession.newEmailAddressDefined {
		return errorCodeNewEmailAddressAlreadySet
	}

	if !verifyAccountIdentifierEmailAddressPattern(newEmailAddress) {
		return errorCodeInvalidEmailAddress
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.emailRateLimit.Consume(newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	newEmailAddressVerificationCode, err := server.setEmailAddressUpdateNewEmailAddress(emailAddressUpdateSession.id, newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update session new email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(newEmailAddress, newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, SessionToken string, emailAddressUpdateSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken        = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !emailAddressUpdateSession.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}
	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailRateLimit.Consume(emailAddressUpdateSession.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddressUpdateSession.newEmailAddress, emailAddressUpdateSession.newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, emailAddressUpdateSession.newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, SessionToken string, emailAddressUpdateSessionToken string, verificationCode string) string {
	const (
		errorCodeInvalidAuthSessionToken        = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeIncorrectVerificationCode      = "incorrect_verification_code"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !emailAddressUpdateSession.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if !emailAddressUpdateSession.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}

	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(emailAddressUpdateSession.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	verificationCodeCorrect := emailAddressUpdateSession.compareNewEmailAddressVerificationCode(verificationCode)
	if !verificationCodeCorrect {
		server.logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id, emailAddressUpdateSession.newEmailAddress)
		return errorCodeIncorrectVerificationCode
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddressUpdateSession.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	oldUserEmailAddress, err := server.completeEmailAddressUpdate(emailAddressUpdateSession.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id, emailAddressUpdateSession.newEmailAddress)

	err = server.sendEmailAddressUpdatedEmail(oldUserEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, oldUserEmailAddress, emailTypeEmailAddressUpdatedNotification)

	return ""
}

func (server *serverStruct) startAccountDeletionAction(requestId string, clientIPAddress string, SessionToken string) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", errorCodeUnexpectedError
	}

	accountDeletionSession, accountDeletionSessionSecret, err := server.createAccountDeletion(authSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logAccountDeletionStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id)

	accountDeletionSessionToken := createSessionToken(accountDeletionSession.id, accountDeletionSessionSecret)

	return accountDeletionSessionToken, ""
}

func (server *serverStruct) cancelAccountDeletionAction(requestId string, clientIPAddress string, SessionToken string, accountDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken     = "invalid_auth_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_session_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate account deletion token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	err = server.deleteAccountDeletionSession(accountDeletionSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete account deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyAccountDeletionUserPasswordAction(requestId string, clientIPAddress string, SessionToken string, accountDeletionSessionToken string, password string) string {
	const (
		errorCodeInvalidAuthSessionToken     = "invalid_auth_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_session_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
		errorCodeIncorrectPassword           = "incorrect_password"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if accountDeletionSession.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordAuthenticationRateLimit.Consume(user.id)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	passwordHash := server.hashUserPassword(password, user.passwordSalt)
	passwordCorrect := constantTimeCompare(user.passwordHash, passwordHash)
	if !passwordCorrect {
		server.logAccountDeletionUserPasswordVerificationFailedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id)
		return errorCodeIncorrectPassword
	}

	err = server.setAccountDeletionSessionAsUserIdentityVerified(accountDeletionSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set account deletion session as user identity verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyAccountDeletionUserPassword, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionUserPasswordVerifiedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id)

	return ""
}

func (server *serverStruct) confirmAccountDeletionAction(requestId string, clientIPAddress string, SessionToken string, accountDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken     = "invalid_auth_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_session_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityNotVerified     = "user_identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(SessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !accountDeletionSession.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	err = server.completeAccountDeletion(accountDeletionSession.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id)

	return ""
}

func (server *serverStruct) startPasswordResetAction(requestId string, clientIPAddress string, emailAddress string) (string, string) {
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
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasswordReset, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailRateLimit.Consume(user.emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	passwordResetSession, passwordResetSessionSecret, err := server.createPasswordResetFromUserEmailAddress(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create password reset: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasswordReset, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordResetStartedRequestEvent(requestId, clientIPAddress, passwordResetSession.id, passwordResetSession.userId, user.emailAddress)

	err = server.sendPasswordResetEmailCodeEmail(user.emailAddress, passwordResetSession.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password reset verification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasswordReset, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasswordResetEmailCode)

	passwordResetSessionToken := createSessionToken(passwordResetSession.id, passwordResetSessionSecret)

	return passwordResetSessionToken, ""
}

func (server *serverStruct) cancelPasswordResetAction(requestId string, clientIPAddress string, passwordResetSessionToken string) string {
	const (
		errorCodeInvalidPasswordResetToken = "invalid_password_reset_session_token"
		errorCodeUnexpectedError           = "unexpected_error"
	)

	passwordResetSession, err := server.validatePasswordResetToken(passwordResetSessionToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasswordReset, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deletePasswordResetSession(passwordResetSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete password reset session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasswordReset, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendPasswordResetEmailCodeAction(requestId string, clientIPAddress string, passwordResetSessionToken string) string {
	const (
		errorCodeInvalidPasswordResetToken   = "invalid_password_reset_session_token"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	passwordResetSession, err := server.validatePasswordResetToken(passwordResetSessionToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordResetSession.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	userEmailAddress, err := server.getPasswordResetUserEmailAddress(passwordResetSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailRateLimit.Consume(userEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendPasswordResetEmailCodeEmail(userEmailAddress, passwordResetSession.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password reset verification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypePasswordResetEmailCode)

	return ""
}

func (server *serverStruct) verifyPasswordResetEmailCodeAction(requestId string, clientIPAddress string, passwordResetSessionToken string, emailCode string) string {
	const (
		errorCodeInvalidPasswordResetToken   = "invalid_password_reset_session_token"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
		errorCodeIncorrectEmailCode          = "incorrect_email_code"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	passwordResetSession, err := server.validatePasswordResetToken(passwordResetSessionToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if passwordResetSession.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	userEmailAddress, err := server.getPasswordResetUserEmailAddress(passwordResetSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userPasswordResetCodeVerificationRateLimit.Consume(passwordResetSession.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	codeCorrect := passwordResetSession.compareEmailCode(emailCode)
	if !codeCorrect {
		server.logPasswordResetCodeVerificationFailedRequestEvent(requestId, clientIPAddress, passwordResetSession.id, passwordResetSession.userId, userEmailAddress)
		return errorCodeIncorrectEmailCode
	}

	server.logPasswordResetCodeVerificationFailedRequestEvent(requestId, clientIPAddress, passwordResetSession.id, passwordResetSession.userId, userEmailAddress)

	err = server.setPasswordResetSessionAsUserIdentityVerified(passwordResetSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set password reset session as user identity verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasswordResetEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasswordResetNewPasswordAction(requestId string, clientIPAddress string, passwordResetSessionToken string, newPassword string) (string, string) {
	const (
		errorCodeInvalidPasswordResetToken   = "invalid_password_reset_session_token"
		errorCodeVerificationCodeNotVerified = "verification_code_not_verified"
		errorCodeInvalidPassword             = "invalid_password"
		errorCodeWeakPassword                = "weak_password"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	passwordResetSession, err := server.validatePasswordResetToken(passwordResetSessionToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return "", errorCodeInvalidPasswordResetToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password reset session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !passwordResetSession.userIdentityVerified {
		return "", errorCodeVerificationCodeNotVerified
	}

	userEmailAddress, err := server.getPasswordResetUserEmailAddress(passwordResetSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get password reset session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !verifyUserPasswordPattern(newPassword) {
		return "", errorCodeInvalidPassword
	}

	newPasswordStrong, err := verifyUserPasswordStrength(newPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !newPasswordStrong {
		return "", errorCodeWeakPassword
	}

	authSession, authSessionSecret, err := server.completePasswordReset(passwordResetSession.id, newPassword)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password reset: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordResetCompletedRequestEvent(requestId, clientIPAddress, passwordResetSession.id, passwordResetSession.userId, userEmailAddress, authSession.id)

	err = server.sendPasswordUpdatedEmail(userEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasswordResetNewPassword, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypePasswordUpdatedNotification)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}
