/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"context"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type User struct {
	UserId       string `json:"userId"`
	ClusterAdmin bool   `json:"clusterAdmin"`
}

type UserEnvelope Envelope[User]

// GetUserHandler returns user information based on request authentication and RBAC permissions.
func (a *App) GetUserHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Authenticate the request
	userInfo, ok := a.requireAuth(w, r, nil)
	if !ok {
		return
	}

	userId := "user@example.com"
	clusterAdmin := true

	// If auth is enabled, retrieve details from the authenticated user info
	if userInfo != nil {
		userId = userInfo.GetName()
		clusterAdmin = a.checkIsClusterAdmin(r.Context(), userInfo)
	}

	user := User{
		UserId:       userId,
		ClusterAdmin: clusterAdmin,
	}
	responseEnvelope := &UserEnvelope{Data: user}
	a.dataResponse(w, r, responseEnvelope)
}

// checkIsClusterAdmin checks if the user has permission to list namespaces at the cluster scope.
func (a *App) checkIsClusterAdmin(ctx context.Context, userInfo user.Info) bool {
	attributes := authorizer.AttributesRecord{
		User:            userInfo,
		Verb:            "list",
		Namespace:       "",
		APIGroup:        "",
		APIVersion:      "v1",
		Resource:        "namespaces",
		ResourceRequest: true,
	}
	decision, _, err := a.RequestAuthZ.Authorize(ctx, attributes)
	if err != nil {
		return false
	}
	return decision == authorizer.DecisionAllow
}
