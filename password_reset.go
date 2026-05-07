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

type passwordResetStruct struct {
	id                   string
	userId               string
	secretHash           []byte
	emailCode            string
	userIdentityVerified bool
	createdAt            time.Time
}

func (passwordReset *passwordResetStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passwordReset.secretHash)
	return hashEqual
}

func (passwordReset *passwordResetStruct) compareEmailCode(emailCode string) bool {
	return constantTimeCompareStrings(emailCode, passwordReset.emailCode)
}

func createPasswordResetToken(passwordResetId string, passwordResetSecret []byte) string {
	encodedPasswordResetSecret := base64.StdEncoding.EncodeToString(passwordResetSecret)
	passwordResetToken := passwordResetId + "." + encodedPasswordResetSecret
	return passwordResetToken
}

const passwordResetTokenCookieName = "password_reset_token"

func (server *serverStruct) setBlankPasswordResetTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     passwordResetTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https,
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) createPasswordResetFromUserEmailAddress(userEmailAddress string) (passwordResetStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailCode := generatePasswordResetEmailCode()

	userIds := []string{}
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO password_reset (id, user_id, secret_hash, email_code, created_at)
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
		return passwordResetStruct{}, nil, errItemConflict
	}
	if err != nil {
		return passwordResetStruct{}, nil, fmt.Errorf("failed to insert into password_reset table: %s", err.Error())
	}
	if len(userIds) < 1 {
		return passwordResetStruct{}, nil, errItemNotFound
	}

	passwordReset := passwordResetStruct{
		id:         id,
		userId:     userIds[0],
		secretHash: secretHash,
		emailCode:  emailCode,
		createdAt:  nowSecondPrecision,
	}

	return passwordReset, secret, nil
}

func (server *serverStruct) getPasswordReset(passwordResetId string) (passwordResetStruct, error) {
	passwordResets := []passwordResetStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, email_code, user_identity_verified, created_at FROM password_reset WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				emailCode := stmt.ColumnText(2)

				userIdentityVerified := stmt.ColumnBool(3)

				createdAt := time.Unix(stmt.ColumnInt64(4), 0)

				passwordReset := passwordResetStruct{
					id:                   passwordResetId,
					userId:               userId,
					secretHash:           secretHash,
					emailCode:            emailCode,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				passwordResets = append(passwordResets, passwordReset)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passwordResetStruct{}, fmt.Errorf("failed to select from password_reset table: %s", err.Error())
	}

	if len(passwordResets) < 1 {
		return passwordResetStruct{}, errItemNotFound
	}

	passwordReset := passwordResets[0]

	if time.Since(passwordReset.createdAt) >= time.Hour {
		return passwordResetStruct{}, errItemNotFound
	}

	return passwordReset, nil
}

func (server *serverStruct) getPasswordResetUserEmailAddress(passwordResetId string) (string, error) {
	userEmailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user.email_address FROM password_reset INNER JOIN user ON password_reset.user_id = user.id WHERE password_reset.id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)

				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from password_reset table: %s", err.Error())
	}
	if len(userEmailAddresses) < 1 {
		return "", errItemNotFound
	}

	userEmailAddress := userEmailAddresses[0]

	return userEmailAddress, nil
}

var errInvalidPasswordResetToken = errors.New("invalid password reset token")

func (server *serverStruct) validatePasswordResetToken(passwordResetToken string) (passwordResetStruct, error) {
	tokenParts := strings.Split(passwordResetToken, ".")
	if len(tokenParts) != 2 {
		return passwordResetStruct{}, errInvalidPasswordResetToken
	}
	resetId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return passwordResetStruct{}, errInvalidPasswordResetToken
	}

	reset, err := server.getPasswordReset(resetId)
	if errors.Is(err, errItemNotFound) {
		return passwordResetStruct{}, errInvalidPasswordResetToken
	}
	if err != nil {
		return passwordResetStruct{}, fmt.Errorf("failed to get password reset: %s", err.Error())
	}

	secretValid := reset.compareSecretAgainstHash(secret)
	if !secretValid {
		return passwordResetStruct{}, errInvalidPasswordResetToken
	}

	return reset, nil
}

func (server *serverStruct) validateRequestPasswordResetToken(r *http.Request) (passwordResetStruct, string, error) {
	passwordResetTokenCookie, err := r.Cookie(passwordResetTokenCookieName)
	if err != nil {
		return passwordResetStruct{}, "", errInvalidPasswordResetToken
	}
	passwordResetToken := passwordResetTokenCookie.Value

	passwordReset, err := server.validatePasswordResetToken(passwordResetToken)
	if errors.Is(err, errInvalidPasswordResetToken) {
		return passwordResetStruct{}, "", errInvalidPasswordResetToken
	}
	if err != nil {
		return passwordResetStruct{}, "", fmt.Errorf("failed to validate password reset token: %s", err.Error())
	}

	return passwordReset, passwordResetToken, nil
}

func (server *serverStruct) setPasswordResetAsUserIdentityVerified(passwordResetId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE password_reset SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passwordResetId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update password_reset table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) completePasswordReset(passwordResetId string, newUserPassword string) (sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	newUserPasswordSalt := generateHashingSalt()
	newUserPasswordHash := server.hashUserPassword(newUserPassword, newUserPasswordSalt)

	sessionId := generateItemId()
	sessionSecret := generateSessionSecret()
	sessionSecretHash := hashSessionSecret(sessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return sessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	userIds := []string{}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE user SET password_hash = ?, password_salt = ? FROM password_reset WHERE user.id = password_reset.user_id AND password_reset.id = ? AND password_reset.user_identity_verified = 1 RETURNING user.id", &sqlitex.ExecOptions{
		Args: []any{newUserPasswordHash, newUserPasswordSalt, passwordResetId},
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
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, errItemNotFound
	}
	userId := userIds[0]

	session := sessionStruct{
		id:         sessionId,
		userId:     userId,
		secretHash: sessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{session.id, session.userId, session.secretHash, session.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return session, sessionSecret, nil
}

func (server *serverStruct) deletePasswordReset(passwordResetId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_reset WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordResetId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from password_reset table: %s", err.Error())
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
