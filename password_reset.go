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

	"golang.org/x/crypto/argon2"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passwordResetStruct struct {
	id                  string
	userId              string
	secretHash          []byte
	codeHash            []byte
	codeSalt            []byte
	firstFactorVerified bool
	createdAt           time.Time
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

func (server *serverStruct) hashPasswordResetCode(code string, salt []byte) []byte {
	server.cpuIntensiveSemaphore.Acquire(context.Background(), 1)
	codeHash := argon2.IDKey([]byte(code), salt, 1, 16*1024, 3, 32)
	server.cpuIntensiveSemaphore.Release(1)
	return codeHash
}

func hashPasswordResetSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
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

var errPasswordResetNotFound = errors.New("password reset not found")

func (server *serverStruct) createPasswordReset(userId string) (passwordResetStruct, []byte, string, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generatePasswordResetSecret()
	secretHash := hashPasswordResetSecret(secret)

	code := generateCode()
	codeSalt := generateHashingSalt()
	codeHash := server.hashPasswordResetCode(code, codeSalt)

	passwordReset := passwordResetStruct{
		id:                  id,
		userId:              userId,
		secretHash:          secretHash,
		codeHash:            codeHash,
		codeSalt:            codeSalt,
		firstFactorVerified: false,
		createdAt:           nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordResetStruct{}, nil, "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO password_reset (id, user_id, secret_hash, code_hash, code_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passwordReset.id,
				passwordReset.userId,
				passwordReset.secretHash,
				passwordReset.codeHash,
				passwordReset.codeSalt,
				passwordReset.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
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
		"SELECT user_id, secret_hash, code_hash, code_salt, first_factor_verified, created_at FROM password_reset WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordResetId},
			ResultFunc: func(stmt *sqlite.Stmt) error {

				userId := stmt.ColumnText(0)
				secretHash := make([]byte, 32)
				stmt.ColumnBytes(1, secretHash)
				codeHash := make([]byte, 32)
				stmt.ColumnBytes(2, codeHash)
				codeSalt := make([]byte, 32)
				stmt.ColumnBytes(3, codeSalt)
				firstFactorVerified := stmt.ColumnBool(4)
				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				passwordReset := passwordResetStruct{
					id:                  passwordResetId,
					userId:              userId,
					secretHash:          secretHash,
					codeHash:            codeHash,
					codeSalt:            codeSalt,
					firstFactorVerified: firstFactorVerified,
					createdAt:           createdAt,
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
		return passwordResetStruct{}, errPasswordResetNotFound
	}

	passwordReset := passwordResets[0]

	if time.Since(passwordReset.createdAt) >= time.Hour*24 {
		return passwordResetStruct{}, errPasswordResetNotFound
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
	if errors.Is(err, errPasswordResetNotFound) {
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

func (server *serverStruct) setPasswordResetAsFirstFactorVerified(passwordResetId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE password_reset SET first_factor_verified = 1 WHERE id = ? AND first_factor_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passwordResetId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update password_reset table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) completePasswordReset(passwordResetId string, newUserPassword string) error {
	newUserPasswordSalt := generateHashingSalt()
	newUserPasswordHash := server.hashUserPassword(newUserPassword, newUserPasswordSalt)

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
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE user SET password_hash = ?, password_salt = ? FROM password_reset WHERE user.id = password_reset.user_id AND password_reset.id = ? AND password_reset.first_factor_verified = 1 RETURNING user.id", &sqlitex.ExecOptions{
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
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return errPasswordResetNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_reset WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordResetId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from password_reset table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM session WHERE user_id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from session table: %s", err.Error())
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

func (server *serverStruct) getPasswordResetUser(passwordResetId string) (userStruct, error) {
	users := []userStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseReadConnection, "SELECT user.id, user.email_address, user.password_hash, user.password_salt, user.created_at FROM password_reset INNER JOIN user ON password_reset.user_id = user.id WHERE password_reset.id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordResetId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := stmt.ColumnText(0)
			emailAddress := stmt.ColumnText(1)

			passwordHash := make([]byte, 32)
			stmt.ColumnBytes(2, passwordHash)

			passwordSalt := make([]byte, 32)
			stmt.ColumnBytes(3, passwordSalt)

			createdAt := time.Unix(stmt.ColumnInt64(4), 0)

			user := userStruct{
				id:           id,
				emailAddress: emailAddress,
				passwordHash: passwordHash,
				passwordSalt: passwordSalt,
				createdAt:    createdAt,
			}

			users = append(users, user)
			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)

	if err != nil {
		return userStruct{}, fmt.Errorf("failed to select from password_reset table: %s", err.Error())
	}

	if len(users) < 1 {
		return userStruct{}, errUserNotFound
	}

	return users[0], nil
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
		return errPasswordResetNotFound
	}
	return nil
}
