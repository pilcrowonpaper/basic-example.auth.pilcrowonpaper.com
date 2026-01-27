package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type emailAddressUpdateStruct struct {
	id                                     string
	sessionId                              string
	secretHash                             []byte
	userIdentityVerified                   bool
	newEmailAddress                        string
	newEmailAddressDefined                 bool
	newEmailAddressVerificationCode        string
	newEmailAddressVerificationCodeDefined bool
	createdAt                              time.Time
}

func (emailAddressUpdate *emailAddressUpdateStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashEmailAddressUpdateSecret(secret)
	hashEqual := constantTimeCompare(hashed, emailAddressUpdate.secretHash)
	return hashEqual
}

func (emailAddressUpdate *emailAddressUpdateStruct) compareNewEmailAddressVerificationCode(newEmailAddressVerificationCode string) bool {
	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		return false
	}
	return constantTimeCompareStrings(newEmailAddressVerificationCode, emailAddressUpdate.newEmailAddressVerificationCode)
}

func generateEmailAddressUpdateSecret() []byte {
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	return secretBytes
}

func hashEmailAddressUpdateSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createEmailAddressUpdateToken(emailAddressUpdateId string, emailAddressUpdateSecret []byte) string {
	encodedEmailAddressUpdateSecret := base64.StdEncoding.EncodeToString(emailAddressUpdateSecret)
	emailAddressUpdateToken := emailAddressUpdateId + "." + encodedEmailAddressUpdateSecret
	return emailAddressUpdateToken
}

const emailAddressUpdateTokenCookieName = "email_address_update_token"

func (server *serverStruct) setBlankEmailAddressUpdateTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     emailAddressUpdateTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https,
	}
	http.SetCookie(w, cookie)
}

var errEmailAddressUpdateNotFound = errors.New("email address update not found")
var errInvalidEmailAddressUpdateToken = errors.New("invalid email address update token")

func (server *serverStruct) createEmailAddressUpdate(sessionId string) (emailAddressUpdateStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateEmailAddressUpdateSecret()
	secretHash := hashEmailAddressUpdateSecret(secret)

	emailAddressUpdate := emailAddressUpdateStruct{
		id:                                     id,
		sessionId:                              sessionId,
		secretHash:                             secretHash,
		userIdentityVerified:                   false,
		newEmailAddressDefined:                 false,
		newEmailAddressVerificationCodeDefined: false,
		createdAt:                              nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO email_address_update (id, session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				emailAddressUpdate.id,
				emailAddressUpdate.sessionId,
				emailAddressUpdate.secretHash,
				emailAddressUpdate.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return emailAddressUpdateStruct{}, nil, fmt.Errorf("failed to insert into email_address_update table: %s", err.Error())
	}

	return emailAddressUpdate, secret, nil
}

func (server *serverStruct) getEmailAddressUpdate(emailAddressUpdateId string) (emailAddressUpdateStruct, error) {
	emailAddressUpdates := []emailAddressUpdateStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, user_identity_verified, new_email_address, new_email_address_verification_code, created_at FROM email_address_update WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				sessionId := stmt.ColumnText(0)
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

				emailAddressUpdate := emailAddressUpdateStruct{
					id:                                     emailAddressUpdateId,
					sessionId:                              sessionId,
					secretHash:                             secretHash,
					userIdentityVerified:                   userIdentityVerified,
					newEmailAddress:                        newEmailAddress,
					newEmailAddressDefined:                 newEmailAddressDefined,
					newEmailAddressVerificationCode:        newEmailAddressVerificationCode,
					newEmailAddressVerificationCodeDefined: newEmailAddressVerificationCodeDefined,
					createdAt:                              createdAt,
				}

				emailAddressUpdates = append(emailAddressUpdates, emailAddressUpdate)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to select from email_address_update table: %s", err.Error())
	}

	if len(emailAddressUpdates) < 1 {
		return emailAddressUpdateStruct{}, errEmailAddressUpdateNotFound
	}

	emailAddressUpdate := emailAddressUpdates[0]

	if time.Since(emailAddressUpdate.createdAt) >= time.Minute*20 {
		return emailAddressUpdateStruct{}, errEmailAddressUpdateNotFound
	}

	return emailAddressUpdate, nil
}

func (server *serverStruct) validateEmailAddressUpdateToken(emailAddressUpdateToken string) (emailAddressUpdateStruct, error) {
	emailAddressUpdateTokenParts := strings.Split(emailAddressUpdateToken, ".")
	if len(emailAddressUpdateTokenParts) != 2 {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateId := emailAddressUpdateTokenParts[0]
	encodedEmailAddressUpdateSecret := emailAddressUpdateTokenParts[1]
	emailAddressUpdateSecret, err := base64.StdEncoding.DecodeString(encodedEmailAddressUpdateSecret)
	if err != nil {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}

	emailAddressUpdate, err := server.getEmailAddressUpdate(emailAddressUpdateId)
	if errors.Is(err, errEmailAddressUpdateNotFound) {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to get email address update: %s", err.Error())
	}

	emailAddressUpdateSecretValid := emailAddressUpdate.compareSecretAgainstHash(emailAddressUpdateSecret)
	if !emailAddressUpdateSecretValid {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}

	return emailAddressUpdate, nil
}

func (server *serverStruct) validateRequestEmailAddressUpdateToken(r *http.Request) (emailAddressUpdateStruct, string, error) {
	emailAddressUpdateTokenCookie, err := r.Cookie(emailAddressUpdateTokenCookieName)
	if err != nil {
		return emailAddressUpdateStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateToken := emailAddressUpdateTokenCookie.Value

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return emailAddressUpdateStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateStruct{}, "", fmt.Errorf("failed to validate email address update token: %s", err.Error())
	}

	return emailAddressUpdate, emailAddressUpdateToken, nil
}

func (server *serverStruct) setEmailAddressUpdateAsUserIdentityVerified(emailAddressUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update SET user_identity_verified = 1 WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update email_address_update table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddress(emailAddressUpdateId string, newEmailAddress string) (string, error) {
	newEmailAddressVerificationCode := generateEmailVerificationCode()

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update SET new_email_address = ?, new_email_address_verification_code = ? WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{newEmailAddress, newEmailAddressVerificationCode, emailAddressUpdateId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return "", fmt.Errorf("failed to update email_address_update table: %s", err.Error())
	}
	return newEmailAddressVerificationCode, nil
}

func (server *serverStruct) completeEmailAddressUpdate(emailAddressUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	userIds := []string{}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE user SET email_address = email_address_update.new_email_address FROM session JOIN email_address_update ON email_address_update.session_id = session.id WHERE user.id = session.user_id AND email_address_update.id = ? RETURNING user.id", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userId := stmt.ColumnText(0)
			userIds = append(userIds, userId)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err) == sqlite.ResultConstraintUnique {
			return errUserEmailAddressAlreadyUsed
		}
		return fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return errEmailAddressUpdateNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from password_reset table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_reset WHERE user_id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from password_reset table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to commit transaction: %s", rollbackErr.Error())
		}
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return nil
}

func (server *serverStruct) deleteEmailAddressUpdate(emailAddressUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to delete from email_address_update table: %s", err.Error())
	}
	return nil
}
