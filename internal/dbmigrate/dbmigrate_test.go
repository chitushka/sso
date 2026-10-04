package dbmigrate

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

type schemaRow struct {
	version uint
	dirty   bool
	err     error
}

func (r schemaRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*uint)) = r.version
	*(dest[1].(*bool)) = r.dirty
	return nil
}

type schemaDB struct{ row pgx.Row }

func (d schemaDB) QueryRow(context.Context, string, ...any) pgx.Row { return d.row }

func TestLatestVersion(t *testing.T) {
	version, err := LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != 13 {
		t.Fatalf("latest migration = %d, want 13", version)
	}
}

func TestCheckSchema(t *testing.T) {
	if err := CheckSchema(context.Background(), schemaDB{row: schemaRow{version: 13}}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []schemaRow{{version: 12}, {version: 13, dirty: true}, {err: errors.New("missing table")}} {
		if err := CheckSchema(context.Background(), schemaDB{row: row}); err == nil {
			t.Fatalf("expected schema check failure for %+v", row)
		}
	}
}
