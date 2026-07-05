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
		r.With(RequirePermission(repo, "roles", "update")).Put("/{roleID}", func(w http.ResponseWriter, r *http.Request) {
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			var req UpdateRoleInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			out, err := svc.UpdateRole(r.Context(), roleID, req)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "role not found")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "roles", "delete")).Delete("/{roleID}", func(w http.ResponseWriter, r *http.Request) {
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			if err := svc.DeleteRole(r.Context(), roleID); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "role not found")
					return
				}
				if errors.Is(err, ErrBuiltInRole) {
					httpx.Error(w, http.StatusConflict, err.Error())
					return
				}
				httpx.Error(w, http.StatusInternalServerError, "failed to delete role")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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

	r.Route("/api/v1/groups", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(RequirePermission(repo, "groups", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.ListGroups(r.Context())
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list groups")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "groups", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateGroupInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			out, err := svc.CreateGroup(r.Context(), req)
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, http.StatusConflict, "group already exists")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusCreated, out)
		})
		r.With(RequirePermission(repo, "groups", "update")).Put("/{groupID}", func(w http.ResponseWriter, r *http.Request) {
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			var req UpdateGroupInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			out, err := svc.UpdateGroup(r.Context(), groupID, req)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "group not found")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "groups", "delete")).Delete("/{groupID}", func(w http.ResponseWriter, r *http.Request) {
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			if err := svc.DeleteGroup(r.Context(), groupID); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "group not found")
					return
				}
				httpx.Error(w, http.StatusInternalServerError, "failed to delete group")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		})
		r.With(RequirePermission(repo, "roles", "read")).Get("/{groupID}/roles", func(w http.ResponseWriter, r *http.Request) {
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			out, err := svc.ListGroupRoles(r.Context(), groupID)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list group roles")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "groups", "assign")).Post("/{groupID}/roles", func(w http.ResponseWriter, r *http.Request) {
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			var req AssignRoleInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			if err := svc.AssignRoleToGroup(r.Context(), groupID, req.RoleID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to assign role")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
		})
		r.With(RequirePermission(repo, "groups", "assign")).Delete("/{groupID}/roles/{roleID}", func(w http.ResponseWriter, r *http.Request) {
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid role id")
				return
			}
			if err := svc.RemoveRoleFromGroup(r.Context(), groupID, roleID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to remove role")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "removed"})
		})
	})

	r.Route("/api/v1/users/{userID}/groups", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(RequirePermission(repo, "groups", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			out, err := svc.ListUserGroups(r.Context(), userID)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list user groups")
				return
			}
			httpx.JSON(w, http.StatusOK, out)
		})
		r.With(RequirePermission(repo, "groups", "assign")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			var req struct {
				GroupID uuid.UUID `json:"group_id"`
			}
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			if err := svc.AssignGroupToUser(r.Context(), userID, req.GroupID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to assign group")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
		})
		r.With(RequirePermission(repo, "groups", "assign")).Delete("/{groupID}", func(w http.ResponseWriter, r *http.Request) {
			userID, err := uuid.Parse(chi.URLParam(r, "userID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid user id")
				return
			}
			groupID, err := uuid.Parse(chi.URLParam(r, "groupID"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid group id")
				return
			}
			if err := svc.RemoveGroupFromUser(r.Context(), userID, groupID); err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to remove group")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "removed"})
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
