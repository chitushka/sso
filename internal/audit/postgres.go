package audit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}
func (r *PostgresRepository) Write(ctx context.Context, e Event) error {
	metadata := e.MetadataJSON
	if metadata == "" {
		metadata = "{}"
	}
	_, err := r.pool.Exec(ctx, `INSERT INTO audit_logs(actor_user_id, action, target_type, target_id, ip, user_agent, metadata_json) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`, e.ActorUserID, e.Action, e.TargetType, e.TargetID, e.IP, e.UserAgent, metadata)
	return err
}
