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
