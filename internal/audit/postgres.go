package audit

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}
func (r *PostgresRepository) Write(ctx context.Context, e Event) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6)`, e.ActorUserID, e.Action, e.TargetType, e.TargetID, e.IP, e.UserAgent)
	return err
}
func (r *PostgresRepository) List(ctx context.Context, f Filter) ([]Event, error) {
	q := `SELECT id,actor_user_id,action,target_type,target_id,ip,user_agent,created_at FROM audit_logs WHERE 1=1`
	args := []any{}
	if f.ActorUserID != nil {
		args = append(args, *f.ActorUserID)
		q += ` AND actor_user_id=$` + strconv.Itoa(len(args))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		q += ` AND action=$` + strconv.Itoa(len(args))
	}
	if f.From != nil {
		args = append(args, *f.From)
		q += ` AND created_at>=$` + strconv.Itoa(len(args))
	}
	if f.To != nil {
		args = append(args, *f.To)
		q += ` AND created_at<=$` + strconv.Itoa(len(args))
	}
	args = append(args, f.Limit)
	q += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(len(args))
	args = append(args, f.Offset)
	q += ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.ActorUserID, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &e.UserAgent, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
