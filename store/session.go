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

package store

import (
	"net/http"

	gsessions "github.com/gorilla/sessions"
)

var SessionName = "Okta-OIDC-Rate-Limiting"

type Session struct {
	name         string
	sessionStore *gsessions.FilesystemStore
}

func NewSession() *Session {
	s := &Session{name: SessionName}
	s.newSessionStore()
	return s
}

func (s *Session) newSessionStore() {
	s.sessionStore = gsessions.NewFilesystemStore("", []byte(SessionName))
	s.sessionStore.MaxLength(0)
}

func (s *Session) Session(req *http.Request) (*gsessions.Session, error) {
	return s.sessionStore.Get(req, SessionName)
}

func (s *Session) SessionFromGivenName(req *http.Request, name string) (*gsessions.Session, error) {
	return s.sessionStore.Get(req, name)
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter, session *gsessions.Session) error {
	return s.sessionStore.Save(r, w, session)
}
