package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type userStruct struct {
	id           string
	emailAddress string
	passwordHash []byte
	passwordSalt []byte
	createdAt    time.Time
}

var errUserNotFound = errors.New("user not found")
var errUserEmailAddressAlreadyUsed = errors.New("user email address already used")

func (server *serverStruct) hashUserPassword(password string, salt []byte) []byte {
	server.cpuIntensiveSemaphore.Acquire(context.Background(), 1)
	passwordHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 3, 32)
	server.cpuIntensiveSemaphore.Release(1)
	return passwordHash
}

func verifyUserPasswordStrength(password string) (bool, error) {
	passwordHashBytes := sha1.Sum([]byte(password))
	passwordHash := hex.EncodeToString(passwordHashBytes[:])
	hashPrefix := passwordHash[0:5]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", hashPrefix)
	res, err := http.DefaultClient.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to send post request to %s: %s", url, err.Error())
	}
	if res.StatusCode != 200 {
		return false, fmt.Errorf("received status code %d from %s", res.StatusCode, url)
	}
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		hashSuffix := strings.ToLower(scanner.Text()[:35])
		if passwordHash == hashPrefix+hashSuffix {
			return false, nil
		}
	}
	return true, nil
}

func verifyUserPasswordPattern(password string) bool {
	length := len([]rune(password))
	return length >= 10 && length <= 100
}

func (server *serverStruct) checkUserEmailAddressAvailability(emailAddress string) (bool, error) {
	userIds := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT id FROM user WHERE email_address = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddress},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userIds = append(userIds, stmt.ColumnText(0))
			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return false, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	emailAddressAvailable := len(userIds) < 1
	return emailAddressAvailable, nil
}

func (server *serverStruct) getUser(userId string) (userStruct, error) {
	users := []userStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseReadConnection, "SELECT email_address, password_hash, password_salt, created_at FROM user WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			emailAddress := stmt.ColumnText(0)

			passwordHash := make([]byte, 32)
			stmt.ColumnBytes(1, passwordHash)

			passwordSalt := make([]byte, 32)
			stmt.ColumnBytes(2, passwordSalt)

			createdAt := time.Unix(stmt.ColumnInt64(3), 0)

			user := userStruct{
				id:           userId,
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
		return userStruct{}, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	if len(users) < 1 {
		return userStruct{}, errUserNotFound
	}

	return users[0], nil
}

func (server *serverStruct) getUserByEmailAddress(emailAddress string) (userStruct, error) {
	users := []userStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseReadConnection, "SELECT id, password_hash, password_salt, created_at FROM user WHERE email_address = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddress},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := stmt.ColumnText(0)

			passwordHash := make([]byte, 32)
			stmt.ColumnBytes(1, passwordHash)

			passwordSalt := make([]byte, 32)
			stmt.ColumnBytes(2, passwordSalt)

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
		return userStruct{}, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	if len(users) < 1 {
		return userStruct{}, errUserNotFound
	}

	return users[0], nil
}

func (server *serverStruct) deleteAllUsers() error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM user", nil)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to delete from user table: %s", err.Error())
	}
	return nil
}
