package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passwordResetStruct struct {
	id                   string
	userId               string
	secretHash           []byte
	emailAddress         string
	codeHash             []byte
	codeSalt             []byte
	userIdentityVerified bool
	createdAt            time.Time
}

func (passwordReset *passwordResetStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashPasswordResetSecret(secret)
	hashEqual := constantTimeCompare(hashed, passwordReset.secretHash)
	return hashEqual
}

func generatePasswordResetSecret() []byte {
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	return secretBytes
}

func hashPasswordResetSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func (server *serverStruct) hashPasswordResetCode(code string, salt []byte) []byte {
	server.cpuIntensiveSemaphore.Acquire(context.Background(), 1)
	codeHash := argon2.IDKey([]byte(code), salt, 1, 16*1024, 3, 32)
	server.cpuIntensiveSemaphore.Release(1)
	runtime.GC()
	return codeHash
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

func (server *serverStruct) createPasswordReset(userId string, emailAddress string) (passwordResetStruct, []byte, string, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generatePasswordResetSecret()
	secretHash := hashPasswordResetSecret(secret)

	code := generatePasswordResetCode()
	codeSalt := generateHashingSalt()
	codeHash := server.hashPasswordResetCode(code, codeSalt)

	passwordReset := passwordResetStruct{
		id:           id,
		userId:       userId,
		secretHash:   secretHash,
		emailAddress: emailAddress,
		codeHash:     codeHash,
		codeSalt:     codeSalt,
		createdAt:    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetStruct{}, nil, "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO password_reset (id, user_id, secret_hash, email_address, code_hash, code_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passwordReset.id,
				passwordReset.userId,
				passwordReset.secretHash,
				passwordReset.emailAddress,
				passwordReset.codeHash,
				passwordReset.codeSalt,
				passwordReset.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passwordResetStruct{}, nil, "", errItemConflict
	}
	if err != nil {
		return passwordResetStruct{}, nil, "", fmt.Errorf("failed to insert into password_reset table: %s", err.Error())
	}

	return passwordReset, secret, code, nil
}

func (server *serverStruct) getPasswordReset(passwordResetId string) (passwordResetStruct, error) {
	passwordResets := []passwordResetStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, email_address, code_hash, code_salt, user_identity_verified, created_at FROM password_reset WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				emailAddress := stmt.ColumnText(2)

				codeHash := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, codeHash)

				codeSalt := make([]byte, stmt.ColumnLen(4))
				stmt.ColumnBytes(4, codeSalt)

				userIdentityVerified := stmt.ColumnBool(5)

				createdAt := time.Unix(stmt.ColumnInt64(6), 0)

				passwordReset := passwordResetStruct{
					id:                   passwordResetId,
					userId:               userId,
					secretHash:           secretHash,
					emailAddress:         emailAddress,
					codeHash:             codeHash,
					codeSalt:             codeSalt,
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

func generatePasswordResetCode() string {
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
