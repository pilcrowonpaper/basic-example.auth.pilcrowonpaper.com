package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type emailAddressUpdateSessionStruct struct {
	id                                     string
	authSessionId                          string
	secretHash                             []byte
	userIdentityVerified                   bool
	newEmailAddress                        string
	newEmailAddressDefined                 bool
	newEmailAddressVerificationCode        string
	newEmailAddressVerificationCodeDefined bool
	createdAt                              time.Time
}

func (emailAddressUpdateSession *emailAddressUpdateSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, emailAddressUpdateSession.secretHash)
	return hashEqual
}

func (emailAddressUpdateSession *emailAddressUpdateSessionStruct) compareNewEmailAddressVerificationCode(newEmailAddressVerificationCode string) bool {
	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		return false
	}
	return constantTimeCompareStrings(newEmailAddressVerificationCode, emailAddressUpdateSession.newEmailAddressVerificationCode)
}

func (server *serverStruct) createEmailAddressUpdate(authSessionId string) (emailAddressUpdateSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailAddressUpdateSession := emailAddressUpdateSessionStruct{
		id:                                     id,
		authSessionId:                          authSessionId,
		secretHash:                             secretHash,
		userIdentityVerified:                   false,
		newEmailAddressDefined:                 false,
		newEmailAddressVerificationCodeDefined: false,
		createdAt:                              nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO email_address_update_session (id, auth_session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				emailAddressUpdateSession.id,
				emailAddressUpdateSession.authSessionId,
				emailAddressUpdateSession.secretHash,
				emailAddressUpdateSession.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return emailAddressUpdateSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return emailAddressUpdateSessionStruct{}, nil, fmt.Errorf("failed to insert into email_address_update_session table: %s", err.Error())
	}

	return emailAddressUpdateSession, secret, nil
}

func (server *serverStruct) getEmailAddressUpdate(emailAddressUpdateSessionId string) (emailAddressUpdateSessionStruct, error) {
	emailAddressUpdateSessions := []emailAddressUpdateSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, user_identity_verified, new_email_address, new_email_address_verification_code, created_at FROM email_address_update_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				authSessionId := stmt.ColumnText(0)
				stmt.ColumnBytes(1, secretHash)
				userIdentityVerified := stmt.ColumnBool(2)

				var newEmailAddress string
				newEmailAddressDefined := false
				if !stmt.ColumnIsNull(3) {
					newEmailAddress = stmt.ColumnText(3)
					newEmailAddressDefined = true
				}

				var newEmailAddressVerificationCode string
				newEmailAddressVerificationCodeDefined := false
				if !stmt.ColumnIsNull(4) {
					newEmailAddressVerificationCode = stmt.ColumnText(4)
					newEmailAddressVerificationCodeDefined = true
				}

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				emailAddressUpdateSession := emailAddressUpdateSessionStruct{
					id:                                     emailAddressUpdateSessionId,
					authSessionId:                          authSessionId,
					secretHash:                             secretHash,
					userIdentityVerified:                   userIdentityVerified,
					newEmailAddress:                        newEmailAddress,
					newEmailAddressDefined:                 newEmailAddressDefined,
					newEmailAddressVerificationCode:        newEmailAddressVerificationCode,
					newEmailAddressVerificationCodeDefined: newEmailAddressVerificationCodeDefined,
					createdAt:                              createdAt,
				}

				emailAddressUpdateSessions = append(emailAddressUpdateSessions, emailAddressUpdateSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return emailAddressUpdateSessionStruct{}, fmt.Errorf("failed to select from email_address_update_session table: %s", err.Error())
	}

	if len(emailAddressUpdateSessions) < 1 {
		return emailAddressUpdateSessionStruct{}, errItemNotFound
	}

	emailAddressUpdateSession := emailAddressUpdateSessions[0]

	if time.Since(emailAddressUpdateSession.createdAt) >= time.Hour {
		return emailAddressUpdateSessionStruct{}, errItemNotFound
	}

	return emailAddressUpdateSession, nil
}

var errInvalidEmailAddressUpdateToken = errors.New("invalid email address update session token")

func (server *serverStruct) validateEmailAddressUpdateToken(emailAddressUpdateSessionToken string) (emailAddressUpdateSessionStruct, error) {
	emailAddressUpdateSessionTokenParts := strings.Split(emailAddressUpdateSessionToken, ".")
	if len(emailAddressUpdateSessionTokenParts) != 2 {
		return emailAddressUpdateSessionStruct{}, errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateSessionId := emailAddressUpdateSessionTokenParts[0]
	encodedEmailAddressUpdateSecret := emailAddressUpdateSessionTokenParts[1]
	emailAddressUpdateSessionSecret, err := base64.StdEncoding.DecodeString(encodedEmailAddressUpdateSecret)
	if err != nil {
		return emailAddressUpdateSessionStruct{}, errInvalidEmailAddressUpdateToken
	}

	emailAddressUpdateSession, err := server.getEmailAddressUpdate(emailAddressUpdateSessionId)
	if errors.Is(err, errItemNotFound) {
		return emailAddressUpdateSessionStruct{}, errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateSessionStruct{}, fmt.Errorf("failed to get email address update session: %s", err.Error())
	}

	emailAddressUpdateSessionSecretValid := emailAddressUpdateSession.compareSecretAgainstHash(emailAddressUpdateSessionSecret)
	if !emailAddressUpdateSessionSecretValid {
		return emailAddressUpdateSessionStruct{}, errInvalidEmailAddressUpdateToken
	}

	return emailAddressUpdateSession, nil
}

const emailAddressUpdateSessionTokenCookieName = "email_address_update_session_token"

func (server *serverStruct) validateRequestEmailAddressUpdateToken(r *http.Request) (emailAddressUpdateSessionStruct, string, error) {
	emailAddressUpdateSessionTokenCookie, err := r.Cookie(emailAddressUpdateSessionTokenCookieName)
	if err != nil {
		return emailAddressUpdateSessionStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateSessionToken := emailAddressUpdateSessionTokenCookie.Value

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return emailAddressUpdateSessionStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateSessionStruct{}, "", fmt.Errorf("failed to validate email address update session token: %s", err.Error())
	}

	return emailAddressUpdateSession, emailAddressUpdateSessionToken, nil
}

func (server *serverStruct) setBlankEmailAddressUpdateTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, emailAddressUpdateSessionTokenCookieName)
}

func (server *serverStruct) setEmailAddressUpdateAsUserIdentityVerified(emailAddressUpdateSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update_session SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update email_address_update_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddress(emailAddressUpdateSessionId string, newEmailAddress string) (string, error) {
	newEmailAddressVerificationCode := generateEmailAddressVerificationCode()

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update_session SET new_email_address = ?, new_email_address_verification_code = ? WHERE id = ? AND new_email_address IS NULL", &sqlitex.ExecOptions{
		Args: []any{newEmailAddress, newEmailAddressVerificationCode, emailAddressUpdateSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", fmt.Errorf("failed to update email_address_update_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return "", errItemNotFound
	}
	return newEmailAddressVerificationCode, nil
}

func (server *serverStruct) completeEmailAddressUpdate(emailAddressUpdateSessionId string) (string, error) {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	oldEmailAddresses := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`SELECT user.email_address FROM email_address_update_session
INNER JOIN auth_session ON email_address_update_session.auth_session_id = auth_session.id
INNER JOIN user ON auth_session.user_id = user.id
WHERE email_address_update_session.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				oldEmailAddress := stmt.ColumnText(0)

				oldEmailAddresses = append(oldEmailAddresses, oldEmailAddress)
				return nil
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to select from email_address_update_session table: %s", err.Error())
	}

	if len(oldEmailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", errItemNotFound
	}
	oldEmailAddress := oldEmailAddresses[0]

	userIds := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE user SET email_address = email_address_update_session.new_email_address
FROM auth_session
INNER JOIN email_address_update_session ON email_address_update_session.auth_session_id = auth_session.id
WHERE user.id = auth_session.user_id
AND email_address_update_session.id = ?
AND email_address_update_session.user_identity_verified = 1
AND email_address_update_session.new_email_address IS NOT NULL
RETURNING id`,
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id := stmt.ColumnText(0)
				userIds = append(userIds, id)
				return nil
			},
		})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return "", errItemConflict
		}
		return "", fmt.Errorf("failed to insert into user table: %s", err.Error())
	}
	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", errItemNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from email_address_update_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_reset_session WHERE user_id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from password_reset_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return oldEmailAddress, nil
}

func (server *serverStruct) deleteEmailAddressUpdate(emailAddressUpdateSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from email_address_update_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
