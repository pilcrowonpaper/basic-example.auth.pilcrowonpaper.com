package main

const (
	requestEventSignupStarted                        = "signup_started"
	requestEventSignupEmailAddressVerified           = "signup_email_address_verified"
	requestEventSignupEmailAddressVerificationFailed = "signup_email_address_verification_failed"
	requestEventSignupCompleted                      = "signup_completed"

	requestEventSignedIn                         = "signed_in"
	requestEventSigninPasswordVerificationFailed = "signin_password_verification_failed"

	requestEventEmailAddressUpdateStarted                           = "email_address_update_started"
	requestEventEmailAddressUpdateUserPasswordVerified              = "email_address_update_user_password_verified"
	requestEventEmailAddressUpdateUserPasswordVerificationFailed    = "email_address_update_user_password_verification_failed"
	requestEventEmailAddressUpdateCompleted                         = "email_address_update_completed"
	requestEventEmailAddressUpdateNewEmailAddressVerificationFailed = "email_address_update_new_email_address_verification_failed"

	requestEventPasswordUpdateStarted                        = "password_update_started"
	requestEventPasswordUpdateUserPasswordVerified           = "password_update_user_password_verified"
	requestEventPasswordUpdateUserPasswordVerificationFailed = "password_update_user_password_verification_failed"
	requestEventPasswordUpdateCompleted                      = "password_update_completed"

	requestEventAccountDeletionStarted                        = "account_deletion_started"
	requestEventAccountDeletionUserPasswordVerified           = "account_deletion_user_password_verified"
	requestEventAccountDeletionUserPasswordVerificationFailed = "account_deletion_user_password_verification_failed"
	requestEventAccountDeletionCompleted                      = "account_deletion_completed"

	requestEventPasswordResetStarted                = "password_reset_started"
	requestEventPasswordResetCodeVerified           = "password_reset_code_verified"
	requestEventPasswordResetCodeVerificationFailed = "password_reset_code_verification_failed"
	requestEventPasswordResetCompleted              = "password_reset_completed"
)

func (server *serverStruct) logSignupStartedRequestEvent(requestId string, clientIPAddress string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupEmailAddressVerifiedRequestEvent(requestId string, clientIPAddress string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupEmailAddressVerificationFailedRequestEvent(requestId string, clientIPAddress string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupCompletedRequestEvent(requestId string, clientIPAddress string, signupId string, emailAddress string, userId string, sessionId string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
		userId:       userId,
		sessionId:    sessionId,
	}

	server.logRequestEvent(requestEventSignupCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignedInRequestEvent(requestId string, clientIPAddress string, userId string, sessionId string) {
	tags := requestEventTagsStruct{
		userId:    userId,
		sessionId: sessionId,
	}

	server.logRequestEvent(requestEventSignedIn, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSigninPasswordVerificationFailedRequestEvent(requestId string, clientIPAddress string, userId string) {
	tags := requestEventTagsStruct{
		userId: userId,
	}

	server.logRequestEvent(requestEventSignedIn, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateStartedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, emailAddressUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateUserPasswordVerifiedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, emailAddressUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateUserPasswordVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateUserPasswordVerificationFailedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, emailAddressUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateUserPasswordVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateCompletedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, emailAddressUpdateId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
		emailAddress:         newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, emailAddressUpdateId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
		emailAddress:         newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateNewEmailAddressVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordUpdateStartedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, passwordUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:        sessionId,
		userId:           userId,
		passwordUpdateId: passwordUpdateId,
	}

	server.logRequestEvent(requestEventPasswordUpdateStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordUpdateUserPasswordVerifiedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, passwordUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:        sessionId,
		userId:           userId,
		passwordUpdateId: passwordUpdateId,
	}

	server.logRequestEvent(requestEventPasswordUpdateUserPasswordVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordUpdateUserPasswordVerificationFailedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, passwordUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:        sessionId,
		userId:           userId,
		passwordUpdateId: passwordUpdateId,
	}

	server.logRequestEvent(requestEventPasswordUpdateUserPasswordVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordUpdateCompletedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, passwordUpdateId string) {
	tags := requestEventTagsStruct{
		sessionId:        sessionId,
		userId:           userId,
		passwordUpdateId: passwordUpdateId,
	}

	server.logRequestEvent(requestEventPasswordUpdateCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionStartedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, accountDeletionId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		accountDeletionId: accountDeletionId,
	}

	server.logRequestEvent(requestEventAccountDeletionStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionUserPasswordVerifiedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, accountDeletionId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		accountDeletionId: accountDeletionId,
	}

	server.logRequestEvent(requestEventAccountDeletionUserPasswordVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionUserPasswordVerificationFailedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, accountDeletionId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		accountDeletionId: accountDeletionId,
	}

	server.logRequestEvent(requestEventAccountDeletionUserPasswordVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionCompletedRequestEvent(requestId string, clientIPAddress string, sessionId string, userId string, accountDeletionId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		accountDeletionId: accountDeletionId,
	}

	server.logRequestEvent(requestEventAccountDeletionCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordResetStartedRequestEvent(requestId string, clientIPAddress string, passwordResetId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		passwordResetId: passwordResetId,
		userId:          userId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventPasswordResetStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordResetCodeVerifiedRequestEvent(requestId string, clientIPAddress string, passwordResetId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		passwordResetId: passwordResetId,
		userId:          userId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventPasswordResetCodeVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordResetCodeVerificationFailedRequestEvent(requestId string, clientIPAddress string, passwordResetId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		passwordResetId: passwordResetId,
		userId:          userId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventPasswordResetCodeVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasswordResetCompletedRequestEvent(requestId string, clientIPAddress string, passwordResetId string, userId string, emailAddress string, sessionId string) {
	tags := requestEventTagsStruct{
		passwordResetId: passwordResetId,
		userId:          userId,
		emailAddress:    emailAddress,
		sessionId:       sessionId,
	}

	server.logRequestEvent(requestEventPasswordResetCompleted, requestId, clientIPAddress, tags)
}
