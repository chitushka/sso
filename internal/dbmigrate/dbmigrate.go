package dbmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chitushka/sso/migrations"
	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type SchemaQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func LatestVersion() (uint, error) {
	files, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return 0, err
	}
	var latest uint64
	for _, name := range files {
		prefix := strings.SplitN(filepath.Base(name), "_", 2)[0]
		version, err := strconv.ParseUint(prefix, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid migration filename %q: %w", name, err)
		}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, errors.New("no embedded migrations")
	}
	return uint(latest), nil
}

func CheckSchema(ctx context.Context, db SchemaQuerier) error {
	latest, err := LatestVersion()
	if err != nil {
		return err
	}
	var version uint
	var dirty bool
	if err := db.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations LIMIT 1`).Scan(&version, &dirty); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database schema migration %d is dirty", version)
	}
	if version != latest {
		return fmt.Errorf("database schema version is %d, expected %d", version, latest)
	}
	return nil
}

// Up applies all pending embedded migrations. It opens its own short-lived
// connection so it can run before the application pool is used.
func Up(databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		return err
	}
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
