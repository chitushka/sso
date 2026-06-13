package rbac

import (
	"errors"
	"net/http"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, repo Repository) {
	r.Route("/api/v1/roles", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(RequirePermission(repo, "roles", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.ListRoles(r.Context())
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list roles")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "roles", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateRoleInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			out, err := svc.CreateRole(r.Context(), req)
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, http.StatusConflict, "role already exists")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusCreated, out)
		})
		r.With(RequirePermission(repo, "permissions", "read")).Get("/{roleID}/permissions", func(w http.ResponseWriter, r *http.Request) {
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			out, err := svc.ListRolePermissions(r.Context(), roleID)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list role permissions")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "permissions", "assign")).Post("/{roleID}/permissions", func(w http.ResponseWriter, r *http.Request) {
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			var req AssignPermissionInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			if err := svc.AssignPermissionToRole(r.Context(), roleID, req.PermissionID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to assign permission")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
		})
		r.With(RequirePermission(repo, "permissions", "assign")).Delete("/{roleID}/permissions/{permissionID}", func(w http.ResponseWriter, r *http.Request) {
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			permissionID, err := uuid.Parse(chi.URLParam(r, "permissionID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid permission id")
				return
			}
			if err := svc.RemovePermissionFromRole(r.Context(), roleID, permissionID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to remove permission")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "removed"})
		})
	})

	r.Route("/api/v1/permissions", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(RequirePermission(repo, "permissions", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.ListPermissions(r.Context())
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list permissions")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
	})

	r.Route("/api/v1/users/{userID}/roles", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(RequirePermission(repo, "roles", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			out, err := svc.ListUserRoles(r.Context(), userID)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list user roles")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "roles", "assign")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			var req AssignRoleInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			if err := svc.AssignRoleToUser(r.Context(), userID, req.RoleID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to assign role")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
		})
		r.With(RequirePermission(repo, "roles", "assign")).Delete("/{roleID}", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			if err := svc.RemoveRoleFromUser(r.Context(), userID, roleID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to remove role")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "removed"})
		})
	})
}
