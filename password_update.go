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

type passwordUpdateStruct struct {
	id                   string
	sessionId            string
	secretHash           []byte
	userIdentityVerified bool
	createdAt            time.Time
}

func (passwordUpdate *passwordUpdateStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashPasswordUpdateSecret(secret)
	hashEqual := constantTimeCompare(hashed, passwordUpdate.secretHash)
	return hashEqual
}

func generatePasswordUpdateSecret() []byte {
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	return secretBytes
}

func hashPasswordUpdateSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createPasswordUpdateToken(passwordUpdateId string, passwordUpdateSecret []byte) string {
	encodedPasswordUpdateSecret := base64.StdEncoding.EncodeToString(passwordUpdateSecret)
	passwordUpdateToken := passwordUpdateId + "." + encodedPasswordUpdateSecret
	return passwordUpdateToken
}

const passwordUpdateTokenCookieName = "password_update_token"

func (server *serverStruct) setBlankPasswordUpdateTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     passwordUpdateTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https,
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) createPasswordUpdate(sessionId string) (passwordUpdateStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generatePasswordUpdateSecret()
	secretHash := hashPasswordUpdateSecret(secret)

	passwordUpdate := passwordUpdateStruct{
		id:                   id,
		sessionId:            sessionId,
		secretHash:           secretHash,
		userIdentityVerified: false,

		createdAt: nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordUpdateStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO password_update (id, session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passwordUpdate.id,
				passwordUpdate.sessionId,
				passwordUpdate.secretHash,
				passwordUpdate.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passwordUpdateStruct{}, nil, errItemConflict
	}
	if err != nil {
		return passwordUpdateStruct{}, nil, fmt.Errorf("failed to insert into password_update table: %s", err.Error())
	}

	return passwordUpdate, secret, nil
}

func (server *serverStruct) getPasswordUpdate(passwordUpdateId string) (passwordUpdateStruct, error) {
	passwordUpdates := []passwordUpdateStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passwordUpdateStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, user_identity_verified, created_at FROM password_update WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordUpdateId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				sessionId := stmt.ColumnText(0)
				stmt.ColumnBytes(1, secretHash)
				userIdentityVerified := stmt.ColumnBool(2)

				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				passwordUpdate := passwordUpdateStruct{
					id:                   passwordUpdateId,
					sessionId:            sessionId,
					secretHash:           secretHash,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				passwordUpdates = append(passwordUpdates, passwordUpdate)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passwordUpdateStruct{}, fmt.Errorf("failed to select from password_update table: %s", err.Error())
	}

	if len(passwordUpdates) < 1 {
		return passwordUpdateStruct{}, errItemNotFound
	}

	passwordUpdate := passwordUpdates[0]

	if time.Since(passwordUpdate.createdAt) >= time.Hour {
		return passwordUpdateStruct{}, errItemNotFound
	}

	return passwordUpdate, nil
}

var errInvalidPasswordUpdateToken = errors.New("invalid password update token")

func (server *serverStruct) validatePasswordUpdateToken(passwordUpdateToken string) (passwordUpdateStruct, error) {
	tokenParts := strings.Split(passwordUpdateToken, ".")
	if len(tokenParts) != 2 {
		return passwordUpdateStruct{}, errInvalidPasswordUpdateToken
	}
	updateId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return passwordUpdateStruct{}, errInvalidPasswordUpdateToken
	}

	update, err := server.getPasswordUpdate(updateId)
	if errors.Is(err, errItemNotFound) {
		return passwordUpdateStruct{}, errInvalidPasswordUpdateToken
	}
	if err != nil {
		return passwordUpdateStruct{}, fmt.Errorf("failed to get password update: %s", err.Error())
	}

	secretValid := update.compareSecretAgainstHash(secret)
	if !secretValid {
		return passwordUpdateStruct{}, errInvalidPasswordUpdateToken
	}

	return update, nil
}

func (server *serverStruct) setPasswordUpdateAsUserIdentityVerified(passwordUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE password_update SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update password_update table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) validateRequestPasswordUpdateToken(r *http.Request) (passwordUpdateStruct, string, error) {
	passwordUpdateTokenCookie, err := r.Cookie(passwordUpdateTokenCookieName)
	if err != nil {
		return passwordUpdateStruct{}, "", errInvalidPasswordUpdateToken
	}
	passwordUpdateToken := passwordUpdateTokenCookie.Value

	passwordUpdate, err := server.validatePasswordUpdateToken(passwordUpdateToken)
	if errors.Is(err, errInvalidPasswordUpdateToken) {
		return passwordUpdateStruct{}, "", errInvalidPasswordUpdateToken
	}
	if err != nil {
		return passwordUpdateStruct{}, "", fmt.Errorf("failed to validate password update token: %s", err.Error())
	}

	return passwordUpdate, passwordUpdateToken, nil
}

func (server *serverStruct) completePasswordUpdate(passwordUpdateId string, newUserPassword string) error {
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
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE user SET password_hash = ?, password_salt = ? FROM session JOIN password_update ON password_update.session_id = session.id WHERE user.id = session.user_id AND password_update.id = ? AND password_update.user_identity_verified = 1 RETURNING user.id", &sqlitex.ExecOptions{
		Args: []any{newUserPasswordHash, newUserPasswordSalt, passwordUpdateId},
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
	affectedCount := databaseWriteConnection.Changes()
	if affectedCount < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return errItemNotFound
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateId},
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
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return nil
}

func (server *serverStruct) deletePasswordUpdate(passwordUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from password_update table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
