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

type passwordUpdateSessionStruct struct {
	id                   string
	authSessionId        string
	secretHash           []byte
	userIdentityVerified bool
	createdAt            time.Time
}

func (passwordUpdateSession *passwordUpdateSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passwordUpdateSession.secretHash)
	return hashEqual
}

func (server *serverStruct) createPasswordUpdateSession(authSessionId string) (passwordUpdateSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	passwordUpdateSession := passwordUpdateSessionStruct{
		id:                   id,
		authSessionId:        authSessionId,
		secretHash:           secretHash,
		userIdentityVerified: false,

		createdAt: nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passwordUpdateSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO password_update_session (id, auth_session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passwordUpdateSession.id,
				passwordUpdateSession.authSessionId,
				passwordUpdateSession.secretHash,
				passwordUpdateSession.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passwordUpdateSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return passwordUpdateSessionStruct{}, nil, fmt.Errorf("failed to insert into password_update_session table: %s", err.Error())
	}

	return passwordUpdateSession, secret, nil
}

func (server *serverStruct) getPasswordUpdateSession(passwordUpdateSessionId string) (passwordUpdateSessionStruct, error) {
	passwordUpdateSessions := []passwordUpdateSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passwordUpdateSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, user_identity_verified, created_at FROM password_update_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passwordUpdateSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				authSessionId := stmt.ColumnText(0)
				stmt.ColumnBytes(1, secretHash)
				userIdentityVerified := stmt.ColumnBool(2)

				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				passwordUpdateSession := passwordUpdateSessionStruct{
					id:                   passwordUpdateSessionId,
					authSessionId:        authSessionId,
					secretHash:           secretHash,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				passwordUpdateSessions = append(passwordUpdateSessions, passwordUpdateSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passwordUpdateSessionStruct{}, fmt.Errorf("failed to select from password_update_session table: %s", err.Error())
	}

	if len(passwordUpdateSessions) < 1 {
		return passwordUpdateSessionStruct{}, errItemNotFound
	}

	passwordUpdateSession := passwordUpdateSessions[0]

	if time.Since(passwordUpdateSession.createdAt) >= time.Hour {
		return passwordUpdateSessionStruct{}, errItemNotFound
	}

	return passwordUpdateSession, nil
}

var errInvalidPasswordUpdateSessionToken = errors.New("invalid password update session token")

func (server *serverStruct) validatePasswordUpdateSessionToken(passwordUpdateSessionToken string) (passwordUpdateSessionStruct, error) {
	tokenParts := strings.Split(passwordUpdateSessionToken, ".")
	if len(tokenParts) != 2 {
		return passwordUpdateSessionStruct{}, errInvalidPasswordUpdateSessionToken
	}
	updateId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return passwordUpdateSessionStruct{}, errInvalidPasswordUpdateSessionToken
	}

	update, err := server.getPasswordUpdateSession(updateId)
	if errors.Is(err, errItemNotFound) {
		return passwordUpdateSessionStruct{}, errInvalidPasswordUpdateSessionToken
	}
	if err != nil {
		return passwordUpdateSessionStruct{}, fmt.Errorf("failed to get password update session: %s", err.Error())
	}

	secretValid := update.compareSecretAgainstHash(secret)
	if !secretValid {
		return passwordUpdateSessionStruct{}, errInvalidPasswordUpdateSessionToken
	}

	return update, nil
}

const passwordUpdateSessionTokenCookieName = "password_update_session_token"

func (server *serverStruct) validateRequestPasswordUpdateSessionToken(r *http.Request) (passwordUpdateSessionStruct, string, error) {
	passwordUpdateSessionTokenCookie, err := r.Cookie(passwordUpdateSessionTokenCookieName)
	if err != nil {
		return passwordUpdateSessionStruct{}, "", errInvalidPasswordUpdateSessionToken
	}
	passwordUpdateSessionToken := passwordUpdateSessionTokenCookie.Value

	passwordUpdateSession, err := server.validatePasswordUpdateSessionToken(passwordUpdateSessionToken)
	if errors.Is(err, errInvalidPasswordUpdateSessionToken) {
		return passwordUpdateSessionStruct{}, "", errInvalidPasswordUpdateSessionToken
	}
	if err != nil {
		return passwordUpdateSessionStruct{}, "", fmt.Errorf("failed to validate password update session token: %s", err.Error())
	}

	return passwordUpdateSession, passwordUpdateSessionToken, nil
}

func (server *serverStruct) setBlankPasswordUpdateSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, passwordUpdateSessionTokenCookieName)
}

func (server *serverStruct) setPasswordUpdateSessionAsUserIdentityVerified(passwordUpdateSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE password_update_session SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateSessionId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to update password_update_session table: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) completePasswordUpdateSession(passwordUpdateSessionId string, newUserPassword string) error {
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
	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE user SET password_hash = ?, password_salt = ?
FROM auth_session
JOIN password_update_session ON password_update_session.auth_session_id = auth_session.id
WHERE user.id = auth_session.user_id
AND password_update_session.id = ?
AND password_update_session.user_identity_verified = 1
RETURNING id`,
		&sqlitex.ExecOptions{
			Args: []any{newUserPasswordHash, newUserPasswordSalt, passwordUpdateSessionId},
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_update_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from password_update_session table: %s", err.Error())
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

func (server *serverStruct) deletePasswordUpdateSession(passwordUpdateSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM password_update_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passwordUpdateSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from password_update_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
