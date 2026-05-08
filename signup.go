package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type signupSessionStruct struct {
	id                           string
	secretHash                   []byte
	emailAddress                 string
	emailAddressVerificationCode string
	emailAddressVerified         bool
	createdAt                    time.Time
}

func (signupSession *signupSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, signupSession.secretHash)
	return hashEqual
}

func (signupSession *signupSessionStruct) compareEmailAddressVerificationCode(emailAddressVerificationCode string) bool {
	return constantTimeCompareStrings(emailAddressVerificationCode, signupSession.emailAddressVerificationCode)
}

func (server *serverStruct) createSignupSession(emailAddress string) (signupSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailAddressVerificationCode := generateEmailAddressVerificationCode()

	signupSession := signupSessionStruct{
		id:                           id,
		secretHash:                   secretHash,
		emailAddress:                 emailAddress,
		emailAddressVerificationCode: emailAddressVerificationCode,
		emailAddressVerified:         false,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return signupSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO signup_session (id, secret_hash, email_address, email_address_verification_code, created_at) VALUES (?, ?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{signupSession.id, signupSession.secretHash, signupSession.emailAddress, signupSession.emailAddressVerificationCode, signupSession.createdAt.Unix()},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return signupSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return signupSessionStruct{}, nil, fmt.Errorf("failed to insert into signup_session table: %s", err.Error())
	}

	return signupSession, secret, nil
}

func (server *serverStruct) getSignupSession(signupSessionId string) (signupSessionStruct, error) {
	signupSessions := []signupSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT secret_hash, email_address, email_address_verification_code, email_address_verified, created_at FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {

			secretHash := make([]byte, 32)
			stmt.ColumnBytes(0, secretHash)
			emailAddress := stmt.ColumnText(1)
			emailAddressVerificationCode := stmt.ColumnText(2)
			emailAddressVerified := stmt.ColumnBool(3)
			createdAt := time.Unix(stmt.ColumnInt64(4), 0)

			signupSession := signupSessionStruct{
				id:                           signupSessionId,
				secretHash:                   secretHash,
				emailAddress:                 emailAddress,
				emailAddressVerificationCode: emailAddressVerificationCode,
				emailAddressVerified:         emailAddressVerified,
				createdAt:                    createdAt,
			}

			signupSessions = append(signupSessions, signupSession)

			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to select from signup_session table: %s", err.Error())
	}

	if len(signupSessions) < 1 {
		return signupSessionStruct{}, errItemNotFound
	}
	signupSession := signupSessions[0]

	if time.Since(signupSession.createdAt) >= time.Hour*24 {
		return signupSessionStruct{}, errItemNotFound
	}

	return signupSession, nil
}

var errInvalidSignupAuthSessionToken = errors.New("invalid signup session token")

func (server *serverStruct) validateSignupAuthSessionToken(signupAuthSessionToken string) (signupSessionStruct, error) {
	signupSessionId, signupSessionSecret, err := parseSessionToken(signupAuthSessionToken)
	if err != nil {
		return signupSessionStruct{}, errInvalidSignupAuthSessionToken
	}

	signupSession, err := server.getSignupSession(signupSessionId)
	if errors.Is(err, errItemNotFound) {
		return signupSessionStruct{}, errInvalidSignupAuthSessionToken
	}
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to get signup session: %s", err.Error())
	}

	secretValid := signupSession.compareSecretAgainstHash(signupSessionSecret)
	if !secretValid {
		return signupSessionStruct{}, errInvalidSignupAuthSessionToken
	}

	return signupSession, nil
}

const signupAuthSessionTokenCookieName = "signup_session_token"

func (server *serverStruct) validateRequestSignupAuthSessionToken(r *http.Request) (signupSessionStruct, string, error) {
	signupAuthSessionTokenCookie, err := r.Cookie(signupAuthSessionTokenCookieName)
	if err != nil {
		return signupSessionStruct{}, "", errInvalidSignupAuthSessionToken
	}
	signupAuthSessionToken := signupAuthSessionTokenCookie.Value

	signupSession, err := server.validateSignupAuthSessionToken(signupAuthSessionToken)
	if errors.Is(err, errInvalidSignupAuthSessionToken) {
		return signupSessionStruct{}, "", errInvalidSignupAuthSessionToken
	}
	if err != nil {
		return signupSessionStruct{}, "", fmt.Errorf("failed to validate signup session token: %s", err.Error())
	}

	return signupSession, signupAuthSessionToken, nil
}

func (server *serverStruct) setBlankSignupAuthSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, signupAuthSessionTokenCookieName)
}

func (server *serverStruct) setSignupSessionAsEmailAddressVerified(signupSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE signup_session SET email_address_verified = 1 WHERE id = ? AND email_address_verified = 0", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update signup_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeSignup(signupSessionId string, userPassword string) (userStruct, authSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	userId := generateItemId()
	userPasswordSalt := generateHashingSalt()
	userPasswordHash := server.hashUserPassword(userPassword, userPasswordSalt)

	authSessionId := generateItemId()
	authSessionSecret := generateSessionSecret()
	authSessionSecretHash := hashSessionSecret(authSessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	emailAddresses := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO user (id, email_address, password_hash, password_salt, created_at)
SELECT ?, email_address, ?, ?, ? FROM signup_session
WHERE id = ? AND email_address_verified = 1
RETURNING email_address`,
		&sqlitex.ExecOptions{
			Args: []any{userId, userPasswordHash, userPasswordSalt, nowSecondPrecision.Unix(), signupSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				emailAddress := stmt.ColumnText(0)
				emailAddresses = append(emailAddresses, emailAddress)
				return nil
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, authSessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}
	if len(emailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, errItemNotFound
	}
	emailAddress := emailAddresses[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to delete from signup_session table: %s", err.Error())
	}

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
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into auth_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	user := userStruct{
		id:           userId,
		emailAddress: emailAddress,
		passwordHash: userPasswordHash,
		passwordSalt: userPasswordSalt,
		createdAt:    nowSecondPrecision,
	}
	return user, authSession, authSessionSecret, nil
}

func (server *serverStruct) deleteSignupSession(signupSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from signup_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
