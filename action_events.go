package main

import (
	"fmt"
	"time"

	"github.com/pilcrowonpaper/go-json"
)

const (
	actionEventUserPasswordAuthenticationSucceeded    = "user_password_authentication_succeeded"
	actionEventUserPasswordAuthenticationFailed       = "user_password_authentication_failed"
	actionEventEmailAddressVerificationSucceeded      = "email_address_verification_succeeded"
	actionEventEmailAddressVerificationFailed         = "email_address_verification_failed"
	actionEventPasswordResetCodeVerificationSucceeded = "password_reset_code_verification_succeeded"
	actionEventPasswordResetCodeVerificationFailed    = "password_reset_code_verification_failed"
	actionEventSessionCreated                         = "session_created"
	actionEventSessionDeleted                         = "session_deleted"
	actionEventAllUserSessionsDeleted                 = "all_user_sessions_deleted"
	actionEventSignupCreated                          = "signup_created"
	actionEventSignupDeleted                          = "signup_deleted"
	actionEventEmailAddressUpdateCreated              = "email_address_update_created"
	actionEventEmailAddressUpdateDeleted              = "email_address_update_deleted"
	actionEventPasswordUpdateCreated                  = "password_update_created"
	actionEventPasswordUpdateDeleted                  = "password_update_deleted"
	actionEventAccountDeletionCreated                 = "account_deletion_created"
	actionEventAccountDeletionDeleted                 = "account_deletion_deleted"
	actionEventPasswordResetCreated                   = "password_reset_created"
	actionEventPasswordResetDeleted                   = "password_reset_deleted"
	actionEventUserCreated                            = "user_created"
	actionEventUserDeleted                            = "user_deleted"
	actionEventUserPasswordUpdated                    = "user_password_updated"
	actionEventUserEmailAddressUpdated                = "user_email_address_updated"
)

func (server *serverStruct) logUserPasswordAuthenticationSucceededActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserPasswordAuthenticationSucceeded, requestId, valuesJSON)
}

func (server *serverStruct) logUserPasswordAuthenticationFailedActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserPasswordAuthenticationFailed, requestId, valuesJSON)
}

func (server *serverStruct) logEmailAddressVerificationSucceededActionEvent(requestId string, emailAddress string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("email_address", emailAddress)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventEmailAddressVerificationSucceeded, requestId, valuesJSON)
}

func (server *serverStruct) logEmailAddressVerificationFailedActionEvent(requestId string, emailAddress string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("email_address", emailAddress)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventEmailAddressVerificationFailed, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordResetCodeVerificationSucceededActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordResetCodeVerificationSucceeded, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordResetCodeVerificationFailedActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordResetCodeVerificationFailed, requestId, valuesJSON)
}

func (server *serverStruct) logSessionCreatedActionEvent(requestId string, sessionId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("session_id", sessionId)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventSessionCreated, requestId, valuesJSON)
}

func (server *serverStruct) logSessionDeletedActionEvent(requestId string, sessionId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("session_id", sessionId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventSessionDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logAllUserSessionsDeletedActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventAllUserSessionsDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logSignupCreatedActionEvent(requestId string, signupId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("signup_id", signupId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventSignupCreated, requestId, valuesJSON)
}

func (server *serverStruct) logSignupDeletedActionEvent(requestId string, signupId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("signup_id", signupId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventSignupDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logEmailAddressUpdateCreatedActionEvent(requestId string, emailAddressUpdateId string, sessionId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("email_address_update_id", emailAddressUpdateId)
	valuesJSONBuilder.AddString("session_id", sessionId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventEmailAddressUpdateCreated, requestId, valuesJSON)
}

func (server *serverStruct) logEmailAddressUpdateDeletedActionEvent(requestId string, emailAddressUpdateId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("email_address_update_id", emailAddressUpdateId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventEmailAddressUpdateDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordUpdateCreatedActionEvent(requestId string, passwordUpdateId string, sessionId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("password_update_id", passwordUpdateId)
	valuesJSONBuilder.AddString("session_id", sessionId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordUpdateCreated, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordUpdateDeletedActionEvent(requestId string, passwordUpdateId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("password_update_id", passwordUpdateId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordUpdateDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logAccountDeletionCreatedActionEvent(requestId string, accountDeletionId string, sessionId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("account_deletion_id", accountDeletionId)
	valuesJSONBuilder.AddString("session_id", sessionId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventAccountDeletionCreated, requestId, valuesJSON)
}

func (server *serverStruct) logAccountDeletionDeletedActionEvent(requestId string, accountDeletionId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("account_deletion_id", accountDeletionId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventAccountDeletionDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordResetCreatedActionEvent(requestId string, passwordResetId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("password_reset_id", passwordResetId)
	valuesJSONBuilder.AddString("userId", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordResetCreated, requestId, valuesJSON)
}

func (server *serverStruct) logPasswordResetDeletedActionEvent(requestId string, passwordResetId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("password_reset_id", passwordResetId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventPasswordResetDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logUserCreatedActionEvent(requestId string, userId string, emailAddress string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSONBuilder.AddString("email_address", emailAddress)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserCreated, requestId, valuesJSON)
}

func (server *serverStruct) logUserDeletedActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserDeleted, requestId, valuesJSON)
}

func (server *serverStruct) logUserPasswordUpdatedActionEvent(requestId string, userId string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserPasswordUpdated, requestId, valuesJSON)
}

func (server *serverStruct) logUserEmailAddressUpdatedActionEvent(requestId string, userId string, newEmailAddress string) {
	valuesJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	valuesJSONBuilder.AddString("user_id", userId)
	valuesJSONBuilder.AddString("new_email_address", newEmailAddress)
	valuesJSON := valuesJSONBuilder.Done()

	server.logActionEvent(actionEventUserEmailAddressUpdated, requestId, valuesJSON)
}

func (server *serverStruct) logActionEvent(eventName string, requestId string, valuesJSON string) {
	if !server.logging.actionEvent {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_event")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("event", eventName)
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddJSON("values", valuesJSON)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}
