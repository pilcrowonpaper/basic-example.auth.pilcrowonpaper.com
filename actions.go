package main

import (
	"errors"
	"fmt"
)

const (
	actionCreateSignup                             = "create_signup"
	actionDeleteSignup                             = "delete_signup"
	actionSendSignupEmailAddressVerificationCode   = "send_signup_email_address_verification_code"
	actionVerifySignupEmailAddressVerificationCode = "verify_signup_email_address_verification_code"
	actionSetSignupPassword                        = "set_signup_password"

	actionSignIn = "sign_in"

	actionDeleteSession     = "delete_session"
	actionDeleteAllSessions = "delete_all_sessions"

	actionCreatePasswordUpdate             = "create_password_update"
	actionDeletePasswordUpdate             = "delete_password_update"
	actionVerifyPasswordUpdateUserPassword = "verify_password_update_user_password"
	actionSetPasswordUpdateNewPassword     = "set_password_update_new_password"

	actionCreateEmailAddressUpdate                                = "create_email_address_update"
	actionDeleteEmailAddressUpdate                                = "delete_email_address_update"
	actionVerifyEmailAddressUpdateUserPassword                    = "verify_email_address_update_user_password"
	actionSetEmailAddressUpdateNewEmailAddress                    = "set_email_address_update_new_email_address"
	actionSendEmailAddressUpdateNewEmailAddressVerificationCode   = "send_email_address_update_new_email_address_verification_code"
	actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode = "verify_email_address_update_new_email_address_verification_code"

	actionCreateAccountDeletion             = "create_account_deletion"
	actionDeleteAccountDeletion             = "delete_account_deletion"
	actionVerifyAccountDeletionUserPassword = "verify_account_deletion_user_password"
	actionConfirmAccountDeletion            = "confirm_account_deletion"

	actionCreatePasswordReset                = "create_password_reset"
	actionDeletePasswordReset                = "delete_password_reset"
	actionVerifyPasswordResetOneTimePassword = "verify_password_reset_one_time_password"
	actionSetPasswordResetNewPassword        = "set_password_reset_new_password"
)

func (server *serverStruct) createSignupAction(requestId string, emailAddress string) (string, string) {
	const (
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeRateLimited             = "rate_limited"
		errorCodeUnexpectedError         = "unexpected_error"
	)

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

	server.logSignupCreatedActionEvent(requestId, signup.id)

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	signupToken := createSignupToken(signup.id, signupSecret)

	return signupToken, ""
}

func (server *serverStruct) deleteSignupAction(requestId string, signupToken string) string {
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

	server.logSignupDeletedActionEvent(requestId, signup.id)

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
		server.logEmailAddressVerificationFailedActionEvent(requestId, signup.emailAddress)
		return errorCodeIncorrectVerificationCode
	}

	err = server.setSignupAsEmailAddressVerified(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup as email address verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressVerificationSucceededActionEvent(requestId, signup.emailAddress)

	return ""
}

func (server *serverStruct) setSignupPasswordAction(requestId string, signupToken string, password string) (string, string) {
	const (
		errorCodeInvalidSignupToken      = "invalid_signup_token"
		errorCodeEmailAddressNotVerified = "email_address_not_verified"
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeInvalidPassword         = "invalid_password"
		errorCodeWeakPassword            = "weak_password"
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

	user, err := server.completeSignup(signup.id, password)
	if errors.Is(err, errSignupNotFound) {
		return "", errorCodeInvalidSignupToken
	}
	if errors.Is(err, errUserEmailAddressAlreadyUsed) {
		return "", errorCodeEmailAddressAlreadyUsed
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logUserCreatedActionEvent(requestId, user.id, user.emailAddress)

	session, sessionSecret, err := server.createSession(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSessionCreatedActionEvent(requestId, session.id, user.id)

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

	emailAddressValid := verifyEmailAddressPattern(emailAddress)
	if !emailAddressValid {
		return "", errorCodeInvalidEmailAddress
	}

	user, err := server.getUserByEmailAddress(emailAddress)
	if errors.Is(err, errUserNotFound) {
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
		server.logUserPasswordAuthenticationFailedActionEvent(requestId, user.id)
		return "", errorCodeIncorrectPassword
	}

	server.logUserPasswordAuthenticationSucceededActionEvent(requestId, user.id)

	session, sessionSecret, err := server.createSession(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) deleteSessionAction(requestId string, sessionToken string) string {
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

	server.logSessionDeletedActionEvent(requestId, session.id)

	return ""
}

func (server *serverStruct) deleteAllSessionsAction(requestId string, sessionToken string) string {
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

	server.logAllUserSessionsDeletedActionEvent(requestId, session.id)

	return ""
}

func (server *serverStruct) createPasswordUpdateAction(requestId string, sessionToken string) (string, string) {
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

	server.logPasswordUpdateCreatedActionEvent(requestId, passwordUpdate.id, session.id)

	passwordUpdateToken := createPasswordUpdateToken(passwordUpdate.id, passwordUpdateSecret)

	return passwordUpdateToken, ""
}

func (server *serverStruct) deletePasswordUpdateAction(requestId string, sessionToken string, passwordUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeUnexpectedError            = "unexpected_error"
	)

	_, err := server.validateSessionToken(sessionToken)
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

	err = server.deletePasswordUpdate(passwordUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete password update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasswordUpdateDeletedActionEvent(requestId, passwordUpdate.id)

	return ""
}

func (server *serverStruct) verifyPasswordUpdateUserPasswordAction(requestId string, sessionToken string, passwordUpdateToken string, password string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken  = "invalid_password_update_token"
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
		return errorCodeInvalidSessionToken
	}

	if passwordUpdate.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errUserNotFound) {
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
		server.logUserPasswordAuthenticationFailedActionEvent(requestId, user.id)
		return errorCodeIncorrectPassword
	}

	server.logUserPasswordAuthenticationSucceededActionEvent(requestId, user.id)

	err = server.setPasswordUpdateAsUserIdentityVerified(passwordUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set password update as user identity verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasswordUpdateNewPasswordAction(requestId string, sessionToken string, passwordUpdateToken string, newPassword string) (string, string) {
	const (
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeUserIdentityNotVerified    = "user_identity_not_verified"
		errorCodeInvalidPassword            = "invalid_password"
		errorCodeWeakPassword               = "weak_password"
		errorCodeUnexpectedError            = "unexpected_error"
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

	passwordUpdate, err := server.validatePasswordUpdateToken(passwordUpdateToken)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate password update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if passwordUpdate.sessionId != session.id {
		return "", errorCodeInvalidSessionToken
	}

	if !passwordUpdate.userIdentityVerified {
		return "", errorCodeUserIdentityNotVerified
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

	err = server.completePasswordUpdate(passwordUpdate.id, newPassword)
	if errors.Is(err, errPasswordUpdateNotFound) {
		return "", errorCodeInvalidPasswordUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logUserPasswordUpdatedActionEvent(requestId, session.userId)

	user, err := server.getUser(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	err = server.sendPasswordUpdatedEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	newSession, newSessionSecret, err := server.createSession(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSessionCreatedActionEvent(requestId, newSession.id, newSession.userId)

	newSessionToken := createSessionToken(newSession.id, newSessionSecret)

	return newSessionToken, ""
}

func (server *serverStruct) createEmailAddressUpdateAction(requestId string, sessionToken string) (string, string) {
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

	server.logEmailAddressUpdateCreatedActionEvent(requestId, emailAddressUpdate.id, session.id)

	emailAddressUpdateToken := createEmailAddressUpdateToken(emailAddressUpdate.id, emailAddressUpdateSecret)

	return emailAddressUpdateToken, ""
}

func (server *serverStruct) deleteEmailAddressUpdateAction(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	_, err := server.validateSessionToken(sessionToken)
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
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteEmailAddressUpdate(emailAddressUpdate.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email address update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateDeletedActionEvent(requestId, emailAddressUpdate.id)

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateUserPasswordAction(requestId string, sessionToken string, emailAddressUpdateToken string, password string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeUserIdentityAlreadyVerified    = "user_identity_already_verified"
		errorCodeIncorrectPassword              = "incorrect_password"
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
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeInvalidSessionToken
	}

	if emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errUserNotFound) {
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
		server.logUserPasswordAuthenticationFailedActionEvent(requestId, user.id)
		return errorCodeIncorrectPassword
	}

	server.logUserPasswordAuthenticationSucceededActionEvent(requestId, user.id)

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
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeInvalidSessionToken
	}

	if !emailAddressUpdate.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	if emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressAlreadySet
	}

	if !verifyEmailAddressPattern(newEmailAddress) {
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

	return ""
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
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
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeInvalidSessionToken
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

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, sessionToken string, emailAddressUpdateToken string, verificationCode string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeUserIdentityNotVerified        = "user_identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeIncorrectVerificationCode      = "incorrect_verification_code"
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
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeInvalidSessionToken
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
		server.logEmailAddressVerificationFailedActionEvent(requestId, emailAddressUpdate.newEmailAddress)
		return errorCodeIncorrectVerificationCode
	}

	server.logEmailAddressVerificationSucceededActionEvent(requestId, emailAddressUpdate.newEmailAddress)

	user, err := server.getUser(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}
	oldEmailAddress := user.emailAddress

	err = server.completeEmailAddressUpdate(emailAddressUpdate.id)
	if errors.Is(err, errEmailAddressUpdateNotFound) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if errors.Is(err, errUserEmailAddressAlreadyUsed) {
		return errorCodeEmailAddressAlreadyUsed
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logUserEmailAddressUpdatedActionEvent(requestId, user.id, emailAddressUpdate.newEmailAddress)

	err = server.sendEmailAddressUpdatedEmail(oldEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) createAccountDeletionAction(requestId string, sessionToken string) (string, string) {
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

	server.logAccountDeletionCreatedActionEvent(requestId, accountDeletion.id, session.id)

	accountDeletionToken := createAccountDeletionToken(accountDeletion.id, accountDeletionSecret)

	return accountDeletionToken, ""
}

func (server *serverStruct) deleteAccountDeletionAction(requestId string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	_, err := server.validateSessionToken(sessionToken)
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

	err = server.deleteAccountDeletion(accountDeletion.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete account deletion: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionDeletedActionEvent(requestId, accountDeletion.id)

	return ""
}

func (server *serverStruct) verifyAccountDeletionUserPasswordAction(requestId string, sessionToken string, accountDeletionToken string, password string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
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
		return errorCodeInvalidSessionToken
	}

	if accountDeletion.userIdentityVerified {
		return errorCodeUserIdentityAlreadyVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errUserNotFound) {
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
		server.logUserPasswordAuthenticationFailedActionEvent(requestId, user.id)
		return errorCodeIncorrectPassword
	}

	server.logUserPasswordAuthenticationSucceededActionEvent(requestId, user.id)

	err = server.setAccountDeletionAsUserIdentityVerified(accountDeletion.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set account deletion as user identity verified: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) confirmAccountDeletionAction(requestId string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeUserIdentityNotVerified     = "user_identity_not_verified"
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
		return errorCodeInvalidSessionToken
	}

	if !accountDeletion.userIdentityVerified {
		return errorCodeUserIdentityNotVerified
	}

	err = server.completeAccountDeletion(accountDeletion.id)
	if errors.Is(err, errAccountDeletionNotFound) {
		return errorCodeInvalidAccountDeletionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete account deletion: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logUserDeletedActionEvent(requestId, session.userId)

	return ""
}

func (server *serverStruct) createPasswordResetAction(requestId string, emailAddress string) (string, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUserNotFound        = "user_not_found"
		errorCodeRateLimited         = "rate_limited"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	if !verifyEmailAddressPattern(emailAddress) {
		return "", errorCodeInvalidEmailAddress
	}

	user, err := server.getUserByEmailAddress(emailAddress)
	if errors.Is(err, errUserNotFound) {
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

	passwordReset, passwordResetSecret, passwordResetVerificationCode, err := server.createPasswordReset(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create password reset: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasswordResetCreatedActionEvent(requestId, passwordReset.id, user.id)

	err = server.sendPasswordResetOneTimePasswordEmail(user.emailAddress, passwordResetVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password reset verification email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passwordResetToken := createPasswordResetToken(passwordReset.id, passwordResetSecret)

	return passwordResetToken, ""
}

func (server *serverStruct) deletePasswordResetAction(requestId string, passwordResetToken string) string {
	const (
		errorCodeInvalidPasswordResetToken = "invalid_password_reset_token"
		errorCodeUnexpectedError           = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errPasswordResetNotFound) {
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

	server.logPasswordResetDeletedActionEvent(requestId, passwordReset.id)

	return ""
}

func (server *serverStruct) verifyPasswordResetOneTimePassword(requestId string, passwordResetToken string, oneTimePassword string) string {
	const (
		errorCodeInvalidPasswordResetToken  = "invalid_password_reset_token"
		errorCodeFirstFactorAlreadyVerified = "first_factor_already_verified"
		errorCodeIncorrectOneTimePassword   = "incorrect_one_time_password"
		errorCodeRateLimited                = "rate_limited"
		errorCodeUnexpectedError            = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errPasswordResetNotFound) {
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

	rateLimitAllowed := server.userPasswordResetOneTimePasswordVerificationRateLimit.Consume(passwordReset.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	verificationCodeHash := server.hashPasswordResetOneTimePassword(oneTimePassword, passwordReset.oneTimePasswordSalt)
	verificationCodeCorrect := constantTimeCompare(verificationCodeHash, passwordReset.oneTimePasswordHash)
	if !verificationCodeCorrect {
		server.logPasswordResetOneTimePasswordVerificationFailedActionEvent(requestId, passwordReset.id)
		return errorCodeIncorrectOneTimePassword
	}

	server.logPasswordResetOneTimePasswordVerificationSucceededActionEvent(requestId, passwordReset.id)

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
		errorCodeUnexpectedError             = "unexpected_error"
	)

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errPasswordResetNotFound) {
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

	err = server.completePasswordReset(passwordReset.id, newPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete password reset: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logUserPasswordUpdatedActionEvent(requestId, passwordReset.userId)

	user, err := server.getUser(passwordReset.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	err = server.sendPasswordUpdatedEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send password update email: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	session, sessionSecret, err := server.createSession(passwordReset.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSessionCreatedActionEvent(requestId, session.id, user.id)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}
