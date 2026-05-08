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

type accountDeletionSessionStruct struct {
	id                   string
	authSessionId        string
	secretHash           []byte
	userIdentityVerified bool
	createdAt            time.Time
}

func (accountDeletionSession *accountDeletionSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, accountDeletionSession.secretHash)
	return hashEqual
}

func (server *serverStruct) createAccountDeletion(authSessionId string) (accountDeletionSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	accountDeletionSession := accountDeletionSessionStruct{
		id:                   id,
		authSessionId:        authSessionId,
		secretHash:           secretHash,
		userIdentityVerified: false,
		createdAt:            nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO account_deletion_session (id, auth_session_id, secret_hash, user_identity_verified, created_at) VALUES (?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				accountDeletionSession.id,
				accountDeletionSession.authSessionId,
				accountDeletionSession.secretHash,
				accountDeletionSession.userIdentityVerified,
				accountDeletionSession.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return accountDeletionSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return accountDeletionSessionStruct{}, nil, fmt.Errorf("failed to insert into account_deletion_session table: %s", err.Error())
	}

	return accountDeletionSession, secret, nil
}

func (server *serverStruct) getAccountDeletion(accountDeletionSessionId string) (accountDeletionSessionStruct, error) {
	accountDeletionSessions := []accountDeletionSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, user_identity_verified, created_at FROM account_deletion_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				authSessionId := stmt.ColumnText(0)
				stmt.ColumnBytes(1, secretHash)
				userIdentityVerified := stmt.ColumnBool(2)
				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				accountDeletionSession := accountDeletionSessionStruct{
					id:                   accountDeletionSessionId,
					authSessionId:        authSessionId,
					secretHash:           secretHash,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				accountDeletionSessions = append(accountDeletionSessions, accountDeletionSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to select from account_deletion_session table: %s", err.Error())
	}

	if len(accountDeletionSessions) < 1 {
		return accountDeletionSessionStruct{}, errItemNotFound
	}

	accountDeletionSession := accountDeletionSessions[0]

	if time.Since(accountDeletionSession.createdAt) >= time.Hour {
		return accountDeletionSessionStruct{}, errItemNotFound
	}

	return accountDeletionSession, nil
}

var errInvalidAccountDeletionSessionToken = errors.New("invalid account deletion session token")

func (server *serverStruct) validateAccountDeletionSessionToken(accountDeletionSessionToken string) (accountDeletionSessionStruct, error) {
	tokenParts := strings.Split(accountDeletionSessionToken, ".")
	if len(tokenParts) != 2 {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}
	accountDeletionSessionId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}

	accountDeletionSession, err := server.getAccountDeletion(accountDeletionSessionId)
	if errors.Is(err, errItemNotFound) {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to get account deletion session: %s", err.Error())
	}

	secretValid := accountDeletionSession.compareSecretAgainstHash(secret)
	if !secretValid {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}

	return accountDeletionSession, nil
}

const accountDeletionSessionTokenCookieName = "account_deletion_session_token"

func (server *serverStruct) validateRequestAccountDeletionSessionToken(r *http.Request) (accountDeletionSessionStruct, string, error) {
	accountDeletionSessionTokenCookie, err := r.Cookie(accountDeletionSessionTokenCookieName)
	if err != nil {
		return accountDeletionSessionStruct{}, "", errInvalidAccountDeletionSessionToken
	}
	accountDeletionSessionToken := accountDeletionSessionTokenCookie.Value

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return accountDeletionSessionStruct{}, "", errInvalidAccountDeletionSessionToken
	}
	if err != nil {
		return accountDeletionSessionStruct{}, "", fmt.Errorf("failed to validate account deletion token: %s", err.Error())
	}

	return accountDeletionSession, accountDeletionSessionToken, nil
}

func (server *serverStruct) setBlankAccountDeletionSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, accountDeletionSessionTokenCookieName)
}

func (server *serverStruct) setAccountDeletionSessionAsUserIdentityVerified(accountDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE account_deletion_session SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{accountDeletionSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update account_deletion_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeAccountDeletion(accountDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`DELETE FROM user WHERE id IN (
SELECT auth_session.user_id FROM auth_session
INNER JOIN account_deletion_session ON auth_session.id = account_deletion_session.auth_session_id
WHERE account_deletion_session.id = ?
AND account_deletion_session.user_identity_verified = 1
)`,
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionSessionId},
		},
	)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from user table: %s", err.Error())
	}
	deleteUserCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if deleteUserCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) deleteAccountDeletionSession(accountDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM account_deletion_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from account_deletion_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
