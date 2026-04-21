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

type accountDeletionStruct struct {
	id                   string
	sessionId            string
	secretHash           []byte
	userIdentityVerified bool
	createdAt            time.Time
}

func (accountDeletion *accountDeletionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashAccountDeletionSecret(secret)
	hashEqual := constantTimeCompare(hashed, accountDeletion.secretHash)
	return hashEqual
}

func generateAccountDeletionSecret() []byte {
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	return secretBytes
}

func hashAccountDeletionSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createAccountDeletionToken(accountDeletionId string, accountDeletionSecret []byte) string {
	encodedAccountDeletionSecret := base64.StdEncoding.EncodeToString(accountDeletionSecret)
	accountDeletionToken := accountDeletionId + "." + encodedAccountDeletionSecret
	return accountDeletionToken
}

const accountDeletionTokenCookieName = "account_deletion_token"

func (server *serverStruct) setBlankAccountDeletionTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     accountDeletionTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https,
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) createAccountDeletion(sessionId string) (accountDeletionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateAccountDeletionSecret()
	secretHash := hashAccountDeletionSecret(secret)

	accountDeletion := accountDeletionStruct{
		id:                   id,
		sessionId:            sessionId,
		secretHash:           secretHash,
		userIdentityVerified: false,
		createdAt:            nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO account_deletion (id, session_id, secret_hash, user_identity_verified, created_at) VALUES (?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				accountDeletion.id,
				accountDeletion.sessionId,
				accountDeletion.secretHash,
				accountDeletion.userIdentityVerified,
				accountDeletion.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return accountDeletionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return accountDeletionStruct{}, nil, fmt.Errorf("failed to insert into account_deletion table: %s", err.Error())
	}

	return accountDeletion, secret, nil
}

func (server *serverStruct) getAccountDeletion(accountDeletionId string) (accountDeletionStruct, error) {
	accountDeletions := []accountDeletionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, user_identity_verified, created_at FROM account_deletion WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				secretHash := make([]byte, 32)

				sessionId := stmt.ColumnText(0)
				stmt.ColumnBytes(1, secretHash)
				userIdentityVerified := stmt.ColumnBool(2)
				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				accountDeletion := accountDeletionStruct{
					id:                   accountDeletionId,
					sessionId:            sessionId,
					secretHash:           secretHash,
					userIdentityVerified: userIdentityVerified,
					createdAt:            createdAt,
				}

				accountDeletions = append(accountDeletions, accountDeletion)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to select from account_deletion table: %s", err.Error())
	}

	if len(accountDeletions) < 1 {
		return accountDeletionStruct{}, errItemNotFound
	}

	accountDeletion := accountDeletions[0]

	if time.Since(accountDeletion.createdAt) >= time.Hour {
		return accountDeletionStruct{}, errItemNotFound
	}

	return accountDeletion, nil
}

var errInvalidAccountDeletionToken = errors.New("invalid account deletion token")

func (server *serverStruct) validateAccountDeletionToken(accountDeletionToken string) (accountDeletionStruct, error) {
	tokenParts := strings.Split(accountDeletionToken, ".")
	if len(tokenParts) != 2 {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}
	accountDeletionId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}

	accountDeletion, err := server.getAccountDeletion(accountDeletionId)
	if errors.Is(err, errItemNotFound) {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to get account deletion: %s", err.Error())
	}

	secretValid := accountDeletion.compareSecretAgainstHash(secret)
	if !secretValid {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}

	return accountDeletion, nil
}

func (server *serverStruct) validateRequestAccountDeletionToken(r *http.Request) (accountDeletionStruct, string, error) {
	accountDeletionTokenCookie, err := r.Cookie(accountDeletionTokenCookieName)
	if err != nil {
		return accountDeletionStruct{}, "", errInvalidAccountDeletionToken
	}
	accountDeletionToken := accountDeletionTokenCookie.Value

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return accountDeletionStruct{}, "", errInvalidAccountDeletionToken
	}
	if err != nil {
		return accountDeletionStruct{}, "", fmt.Errorf("failed to validate account deletion token: %s", err.Error())
	}

	return accountDeletion, accountDeletionToken, nil
}

func (server *serverStruct) setAccountDeletionAsUserIdentityVerified(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE account_deletion SET user_identity_verified = 1 WHERE id = ? AND user_identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update account_deletion table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeAccountDeletion(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM user WHERE id IN (SELECT session.user_id FROM session INNER JOIN account_deletion ON session.id = account_deletion.session_id WHERE account_deletion.id = ? AND account_deletion.user_identity_verified = 1)", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
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

func (server *serverStruct) deleteAccountDeletion(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM account_deletion WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from account_deletion table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
