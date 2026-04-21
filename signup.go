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

type signupStruct struct {
	id                           string
	secretHash                   []byte
	emailAddress                 string
	emailAddressVerificationCode string
	emailAddressVerified         bool
	createdAt                    time.Time
}

func (signup *signupStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSignupSecret(secret)
	hashEqual := constantTimeCompare(hashed, signup.secretHash)
	return hashEqual
}

func (signup *signupStruct) compareEmailAddressVerificationCode(emailAddressVerificationCode string) bool {
	return constantTimeCompareStrings(emailAddressVerificationCode, signup.emailAddressVerificationCode)
}

func generateSignupSecret() []byte {
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	return secretBytes
}

func hashSignupSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createSignupToken(signupId string, signupSecret []byte) string {
	encodedSignupSecret := base64.StdEncoding.EncodeToString(signupSecret)
	signupToken := signupId + "." + encodedSignupSecret
	return signupToken
}

const signupTokenCookieName = "signup_token"

func (server *serverStruct) setBlankSignupTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     signupTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https,
	}
	http.SetCookie(w, cookie)
}

var errInvalidSignupToken = errors.New("invalid signup token")

func (server *serverStruct) createSignup(emailAddress string) (signupStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSignupSecret()
	secretHash := hashSignupSecret(secret)

	emailAddressVerificationCode := generateEmailAddressVerificationCode()

	signup := signupStruct{
		id:                           id,
		secretHash:                   secretHash,
		emailAddress:                 emailAddress,
		emailAddressVerificationCode: emailAddressVerificationCode,
		emailAddressVerified:         false,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return signupStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO signup (id, secret_hash, email_address, email_address_verification_code, created_at) VALUES (?, ?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{signup.id, signup.secretHash, signup.emailAddress, signup.emailAddressVerificationCode, signup.createdAt.Unix()},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return signupStruct{}, nil, errItemConflict
	}
	if err != nil {
		return signupStruct{}, nil, fmt.Errorf("failed to insert into signup table: %s", err.Error())
	}

	return signup, secret, nil
}

func (server *serverStruct) getSignup(signupId string) (signupStruct, error) {
	signups := []signupStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT secret_hash, email_address, email_address_verification_code, email_address_verified, created_at FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
		ResultFunc: func(stmt *sqlite.Stmt) error {

			secretHash := make([]byte, 32)
			stmt.ColumnBytes(0, secretHash)
			emailAddress := stmt.ColumnText(1)
			emailAddressVerificationCode := stmt.ColumnText(2)
			emailAddressVerified := stmt.ColumnBool(3)
			createdAt := time.Unix(stmt.ColumnInt64(4), 0)

			signup := signupStruct{
				id:                           signupId,
				secretHash:                   secretHash,
				emailAddress:                 emailAddress,
				emailAddressVerificationCode: emailAddressVerificationCode,
				emailAddressVerified:         emailAddressVerified,
				createdAt:                    createdAt,
			}

			signups = append(signups, signup)

			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to select from signup table: %s", err.Error())
	}

	if len(signups) < 1 {
		return signupStruct{}, errItemNotFound
	}
	signup := signups[0]

	if time.Since(signup.createdAt) >= time.Hour*24 {
		return signupStruct{}, errItemNotFound
	}

	return signup, nil
}

func (server *serverStruct) validateSignupToken(signupToken string) (signupStruct, error) {
	tokenParts := strings.Split(signupToken, ".")
	if len(tokenParts) != 2 {
		return signupStruct{}, errInvalidSignupToken
	}
	signupId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return signupStruct{}, errInvalidSignupToken
	}

	signup, err := server.getSignup(signupId)
	if errors.Is(err, errItemNotFound) {
		return signupStruct{}, errInvalidSignupToken
	}
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get signup: %s", err.Error())
	}

	secretValid := signup.compareSecretAgainstHash(secret)
	if !secretValid {
		return signupStruct{}, errInvalidSignupToken
	}

	return signup, nil
}

func (server *serverStruct) validateRequestSignupToken(r *http.Request) (signupStruct, string, error) {
	signupTokenCookie, err := r.Cookie(signupTokenCookieName)
	if err != nil {
		return signupStruct{}, "", errInvalidSignupToken
	}
	signupToken := signupTokenCookie.Value

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return signupStruct{}, "", errInvalidSignupToken
	}
	if err != nil {
		return signupStruct{}, "", fmt.Errorf("failed to validate signup token: %s", err.Error())
	}

	return signup, signupToken, nil
}

func (server *serverStruct) setSignupAsEmailAddressVerified(signupId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE signup SET email_address_verified = 1 WHERE id = ? AND email_address_verified = 0", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update signup table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeSignup(signupId string, userPassword string) (userStruct, sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	userId := generateItemId()
	userPasswordSalt := generateHashingSalt()
	userPasswordHash := server.hashUserPassword(userPassword, userPasswordSalt)

	sessionId := generateItemId()
	sessionSecret := generateSessionSecret()
	sessionSecretHash := hashSessionSecret(sessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	emailAddresses := []string{}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO user (id, email_address, password_hash, password_salt, created_at) SELECT ?, signup.email_address, ?, ?, ? FROM signup WHERE signup.id = ? AND signup.email_address_verified = 1 RETURNING user.email_address", &sqlitex.ExecOptions{
		Args: []any{userId, userPasswordHash, userPasswordSalt, nowSecondPrecision.Unix(), signupId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			emailAddress := stmt.ColumnText(0)
			emailAddresses = append(emailAddresses, emailAddress)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, sessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}
	if len(emailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, errItemNotFound
	}
	emailAddress := emailAddresses[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}

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
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	user := userStruct{
		id:           userId,
		emailAddress: emailAddress,
		passwordHash: userPasswordHash,
		passwordSalt: userPasswordSalt,
		createdAt:    nowSecondPrecision,
	}
	return user, session, sessionSecret, nil
}

func (server *serverStruct) deleteSignup(signupId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
