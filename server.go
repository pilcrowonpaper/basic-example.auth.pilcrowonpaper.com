package main

import (
	"fmt"
	"net/http"
	"runtime"
	"server/ratelimit"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type serverStruct struct {
	emailClient emailClientInterface

	databaseReadConnectionPool  *sqlitex.Pool
	databaseWriteConnectionPool *sqlitex.Pool
	cpuIntensiveSemaphore       *semaphore.Weighted
	https                       bool

	logging serverLoggingStruct

	userPasswordAuthenticationRateLimit                   *ratelimit.LimitStruct
	emailAddressVerificationRateLimit                     *ratelimit.LimitStruct
	userPasswordResetOneTimePasswordVerificationRateLimit *ratelimit.LimitStruct
	emailRateLimit                                        *ratelimit.LimitStruct
}

type serverLoggingStruct struct {
	actionEvent   bool
	actionError   bool
	backgroundJob bool
	actionResult  bool
}

type serverFlagsStruct struct {
	https bool
}

func createServer(emailClient emailClientInterface, flags serverFlagsStruct, logging serverLoggingStruct) (*serverStruct, error) {
	databaseFilename := "main.db"

	databaseReadConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: runtime.NumCPU(),
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite read connection pool: %s", err.Error())
	}

	databaseWriteConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: 1,
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite write connection pool: %s", err.Error())
	}

	cpuIntensiveSemaphore := semaphore.NewWeighted(int64(runtime.NumCPU()))

	userPasswordAuthenticationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailAddressVerificationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	userPasswordResetOneTimePasswordVerificationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailRateLimit := ratelimit.NewLimit(1_000, 3, 30*time.Minute)

	server := &serverStruct{
		emailClient:                         emailClient,
		databaseReadConnectionPool:          databaseReadConnectionPool,
		databaseWriteConnectionPool:         databaseWriteConnectionPool,
		cpuIntensiveSemaphore:               cpuIntensiveSemaphore,
		https:                               flags.https,
		logging:                             logging,
		userPasswordAuthenticationRateLimit: userPasswordAuthenticationRateLimit,
		emailAddressVerificationRateLimit:   emailAddressVerificationRateLimit,
		userPasswordResetOneTimePasswordVerificationRateLimit: userPasswordResetOneTimePasswordVerificationRateLimit,
		emailRateLimit: emailRateLimit,
	}
	return server, nil
}

func (server *serverStruct) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestId := r.Header.Get("X-Railway-Request-Id")
	if requestId == "" {
		requestId = generateLongItemId()
	}

	pathParts := strings.Split(r.URL.Path, "/")[1:]

	// Remove single trailing slash
	if len(pathParts) > 0 && pathParts[len(pathParts)-1] == "" {
		pathParts = pathParts[:len(pathParts)-1]
	}

	// GET /
	if len(pathParts) == 0 && r.Method == "GET" {
		server.homePageRoute(w, r, requestId)
		return
	}

	// /sign-up
	if len(pathParts) > 0 && pathParts[0] == "sign-up" {
		// GET /sign-up
		if len(pathParts) == 1 && r.Method == "GET" {
			server.signUpPageRoute(w, r, requestId)
			return
		}

		// GET /sign-up/verify-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-email-address" && r.Method == "GET" {
			server.signUpVerifyEmailAddressPageRoute(w, r, requestId)
			return
		}

		// GET /sign-up/set-password
		if len(pathParts) == 2 && pathParts[1] == "set-password" && r.Method == "GET" {
			server.signUpSetPasswordPageRoute(w, r, requestId)
			return
		}
	}

	// GET /sign-in
	if len(pathParts) == 1 && pathParts[0] == "sign-in" && r.Method == "GET" {
		server.signInPageRoute(w, r, requestId)
		return
	}

	// GET /account
	if len(pathParts) == 1 && pathParts[0] == "account" && r.Method == "GET" {
		server.accountPageRoute(w, r, requestId)
		return
	}

	// /update-password
	if len(pathParts) > 0 && pathParts[0] == "update-password" {
		// GET /update-password/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.updatePasswordVerifyPasswordPageRoute(w, r, requestId)
			return
		}

		// GET /update-password/set-new-password
		if len(pathParts) == 2 && pathParts[1] == "set-new-password" && r.Method == "GET" {
			server.updatePasswordSetNewPasswordPageRoute(w, r, requestId)
			return
		}
	}

	// /update-email-address
	if len(pathParts) > 0 && pathParts[0] == "update-email-address" {
		// GET /update-email-address/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.updateEmailAddressVerifyPasswordPageRoute(w, r, requestId)
			return
		}

		// GET /update-email-address/set-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "set-new-email-address" && r.Method == "GET" {
			server.updateEmailAddressSetNewEmailAddressPageRoute(w, r, requestId)
			return
		}

		// GET /update-email-address/verify-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-new-email-address" && r.Method == "GET" {
			server.updateEmailAddressVerifyNewEmailAddressPageRoute(w, r, requestId)
			return
		}
	}

	// /delete-account
	if len(pathParts) > 0 && pathParts[0] == "delete-account" {
		// GET /delete-account/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.deleteAccountVerifyPasswordPageRoute(w, r, requestId)
			return
		}

		// GET /delete-account/confirm
		if len(pathParts) == 2 && pathParts[1] == "confirm" && r.Method == "GET" {
			server.deleteAccountConfirmPageRoute(w, r, requestId)
			return
		}
	}

	// /reset-password
	if len(pathParts) > 0 && pathParts[0] == "reset-password" {
		// GET /reset-password
		if len(pathParts) == 1 && r.Method == "GET" {
			server.resetPasswordPageRoute(w, r, requestId)
			return
		}

		// GET /reset-password/verify-one-time-password
		if len(pathParts) == 2 && pathParts[1] == "verify-one-time-password" && r.Method == "GET" {
			server.resetPasswordVerifyOneTimePasswordPageRoute(w, r, requestId)
			return
		}

		// GET /reset-password/set-new-password
		if len(pathParts) == 2 && pathParts[1] == "set-new-password" && r.Method == "GET" {
			server.resetPasswordSetNewPasswordPageRoute(w, r, requestId)
			return
		}
	}

	// POST /action
	if len(pathParts) == 1 && pathParts[0] == "action" && r.Method == "POST" {
		server.actionRoute(w, r, requestId)
		return
	}

	w.WriteHeader(404)
	w.Write([]byte("The page you're looking for doesn't exist."))
}
