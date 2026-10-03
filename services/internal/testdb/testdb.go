// Package testdb gives each test its own Postgres database on the server named by
// TEST_DATABASE_URL, and skips the test when that variable is unset.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// URL creates an empty database and returns its connection string; the database is dropped when
// the test ends.
func URL(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	name := "test_" + hex.EncodeToString(suffix[:])
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	_ = conn.Close(ctx)
	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), admin)
		if err != nil {
			return
		}
		defer conn.Close(context.Background())
		_, _ = conn.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}
