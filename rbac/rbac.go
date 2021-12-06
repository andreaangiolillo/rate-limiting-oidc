// Copyright 2021 MongoDB Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rbac

import (
	"log"

	"github.com/casbin/casbin/v2"
)

type RBAC struct {
	Enforcer *casbin.Enforcer
}

func (rbac *RBAC) Enforce(groups []interface{}, resource string, action string) bool {
	log.Print(groups)

	for _, group := range groups {
		if res, _ := rbac.Enforcer.Enforce(group, resource, action); res {
			log.Printf("%s can %s the resource %s", group, action, resource)
			return true
		}
		log.Printf("%s cannot %s the resource %s", group, action, resource)
	}

	return false
}
