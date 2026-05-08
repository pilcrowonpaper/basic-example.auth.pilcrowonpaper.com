package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passwordResetSessionStruct struct {
	id                   string
	userId               string
	secretHash           []byte
	emailCode            string
	userIdentityVerified bool
	createdAt            time.Time
}

func (passwordResetSession *passwordResetSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passwordResetSession.secretHash)
	return hashEqual
}

func (passwordResetSession *passwordResetSessionStruct) compareEmailCode(emailCode string) bool {
	return constantTimeCompareStrings(emailCode, passwordResetSession.emailCode)
}

func (server *serverStruct) createPasswordResetFromUserEmailAddress(userEmailAddress string) (passwordResetSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailCode := generatePasswordResetEmailCode()

	userIds := []string{}
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO password_reset_session (id, user_id, secret_hash, email_code, created_at)
SELECT ?, user.id, ?, ?, ? FROM user
WHERE user.email_address = ?
RETURNING user_id`,
		&sqlitex.ExecOptions{
			Args: []any{
				id,
				secretHash,
				emailCode,
				nowSecondPrecision.Unix(),
				userEmailAddress,
			},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)
				userIds = append(userIds, userId)
				return nil
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passwordResetSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return passwordResetSessionStruct{}, nil, fmt.Errorf("failed to insert into password_reset_session table: %s", err.Error())
	}
	if len(userIds) < 1 {
		return passwordResetSessionStruct{}, nil, errItemNotFound
	}

	passwordResetSession := passwordResetSessionStruct{
		id:         id,
		userId:     userIds[0],
		secretHash: secretHash,
		emailCode:  emailCode,
		createdAt:  nowSecondPrecision,
	}

	return passwordResetSession, secret, nil
}

func (server *serverStruct) getPasswordReset(passwordResetSessionId string) (passwordResetSessionStruct, error) {
	passwordResetSessions := []passwordResetSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, email_code, user_identity_verified, created_at FROM password_reset_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				emailCode := stmt.ColumnText(2)

				userIdentityVerified := stmt.ColumnBool(3)

				createdAt := time.Unix(stmt.ColumnInt64(4), 0)

				passwordResetSession := passwordResetSessionStruct{
					id:                   passwordResetSessionId,
					userId:               userId,
					secretHash:           secretHash,
					emailCode:            emailCode,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				passwordResetSessions = append(passwordResetSessions, passwordResetSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passwordResetSessionStruct{}, fmt.Errorf("failed to select from password_reset_session table: %s", err.Error())
	}

	if len(passwordResetSessions) < 1 {
		return passwordResetSessionStruct{}, errItemNotFound
	}

	passwordResetSession := passwordResetSessions[0]

	if time.Since(passwordResetSession.createdAt) >= time.Hour {
		return passwordResetSessionStruct{}, errItemNotFound
	}

	return passwordResetSession, nil
}

func (server *serverStruct) getPasswordResetUserEmailAddress(passwordResetSessionId string) (string, error) {
	userEmailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user.email_address FROM password_reset_session INNER JOIN user ON password_reset_session.user_id = user.id WHERE password_reset_session.id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)

				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from password_reset_session table: %s", err.Error())
	}
	if len(userEmailAddresses) < 1 {
		return "", errItemNotFound
	}

	userEmailAddress := userEmailAddresses[0]

	return userEmailAddress, nil
}

var errInvalidPasswordResetToken = errors.New("invalid password reset session token")

func (server *serverStruct) validatePasswordResetToken(passwordResetSessionToken string) (passwordResetSessionStruct, error) {
	tokenParts := strings.Split(passwordResetSessionToken, ".")
	if len(tokenParts) != 2 {
		return passwordResetSessionStruct{}, errInvalidPasswordResetToken
	}
	resetId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return passwordResetSessionStruct{}, errInvalidPasswordResetToken
	}

	reset, err := server.getPasswordReset(resetId)
	if errors.Is(err, errItemNotFound) {
		return passwordResetSessionStruct{}, errInvalidPasswordResetToken
	}
	if err != nil {
		return passwordResetSessionStruct{}, fmt.Errorf("failed to get password reset session: %s", err.Error())
	}

	secretValid := reset.compareSecretAgainstHash(secret)
	if !secretValid {
		return passwordResetSessionStruct{}, errInvalidPasswordResetToken
	}

	return reset, nil
}

const passwordResetSessionTokenCookieName = "password_reset_session_token"

func (server *serverStruct) validateRequestPasswordResetToken(r *http.Request) (passwordResetSessionStruct, string, error) {
	passwordResetSessionTokenCookie, err := r.Cookie(passwordResetSessionTokenCookieName)
	if err != nil {
		return passwordResetSessionStruct{}, "", errInvalidPasswordResetToken
	}
	passwordResetSessionToken := passwordResetSessionTokenCookie.Value

	passwordResetSession, err := server.validatePasswordResetToken(passwordResetSessionToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return passwordResetSessionStruct{}, "", errInvalidPasswordResetToken
	}
	if err != nil {
		return passwordResetSessionStruct{}, "", fmt.Errorf("failed to validate password reset session token: %s", err.Error())
	}

	return passwordResetSession, passwordResetSessionToken, nil
}

func (server *serverStruct) setBlankPasswordResetSessonTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, passwordResetSessionTokenCookieName)
}

func (server *serverStruct) setPasswordResetSessionAsUserIdentityVerified(passwordResetSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE password_reset_session SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passwordResetSessionId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update password_reset_session table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) completePasswordReset(passwordResetSessionId string, newUserPassword string) (authSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	newUserPasswordSalt := generateHashingSalt()
	newUserPasswordHash := server.hashUserPassword(newUserPassword, newUserPasswordSalt)

	authSessionId := generateItemId()
	authSessionSecret := generateSessionSecret()
	authSessionSecretHash := hashSessionSecret(authSessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return authSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return authSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	userIds := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE user SET password_hash = ?, password_salt = ? FROM password_reset_session
WHERE user.id = password_reset_session.user_id
AND password_reset_session.id = ?
AND password_reset_session.user_identity_verified = 1
RETURNING id`,
		&sqlitex.ExecOptions{
			Args: []any{newUserPasswordHash, newUserPasswordSalt, passwordResetSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)
				userIds = append(userIds, userId)
				return nil
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, errItemNotFound
	}
	userId := userIds[0]

	authSession := authSessionStruct{
		id:         authSessionId,
		userId:     userId,
		secretHash: authSessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO auth_session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{authSession.id, authSession.userId, authSession.secretHash, authSession.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to insert into auth_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return authSession, authSessionSecret, nil
}

func (server *serverStruct) deletePasswordResetSession(passwordResetSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_reset_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordResetSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from password_reset_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func generatePasswordResetEmailCode() string {
	emailCodeBytes := make([]byte, 5)
	rand.Read(emailCodeBytes)
	emailCode := base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").EncodeToString(emailCodeBytes)
	return emailCode
}

func formatPasswordResetCode(code string) string {
	stringBytes := make([]byte, 9)
	stringBytes[0] = code[0]
	stringBytes[1] = code[1]
	stringBytes[2] = code[2]
	stringBytes[3] = code[3]
	stringBytes[4] = '-'
	stringBytes[5] = code[4]
	stringBytes[6] = code[5]
	stringBytes[7] = code[6]
	stringBytes[8] = code[7]
	return string(stringBytes)
}
