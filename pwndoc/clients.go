package pwndoc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Contact is a client contact at a company. (pwndoc calls these "clients"; the
// type is named Contact here to avoid colliding with the API Client type. The
// service is still c.Clients to match pwndoc's terminology and routes.)
type Contact struct {
	ID        string      `json:"_id,omitempty"`
	Email     string      `json:"email"` // required
	Firstname string      `json:"firstname,omitempty"`
	Lastname  string      `json:"lastname,omitempty"`
	Phone     string      `json:"phone,omitempty"`
	Cell      string      `json:"cell,omitempty"`
	Title     string      `json:"title,omitempty"`
	Company   *CompanyRef `json:"company,omitempty"` // resolved by {name}; returned as {_id} or {name}
}

// UnmarshalJSON lets a CompanyRef decode from either a bare id string (as
// returned when a client is created) or an object ({_id} / {name}).
func (r *CompanyRef) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var id string
		if err := json.Unmarshal(data, &id); err != nil {
			return err
		}
		r.ID = id
		return nil
	}
	type alias CompanyRef
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = CompanyRef(a)
	return nil
}

// ClientsService manages client contacts.
type ClientsService struct{ c *Client }

// List returns all client contacts.
func (s *ClientsService) List(ctx context.Context) ([]Contact, error) {
	return call[[]Contact](ctx, s.c, apiReq{method: http.MethodGet, path: "/clients", op: "Clients.List"})
}

// Create creates a client contact. Email is required; set Company.Name to
// associate (or auto-create) a company.
func (s *ClientsService) Create(ctx context.Context, p Contact) (*Contact, error) {
	out, err := call[Contact](ctx, s.c, apiReq{method: http.MethodPost, path: "/clients", body: p, op: "Clients.Create"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Update updates the client contact with the given id and returns the stored
// record (re-read, since pwndoc returns only a status message).
func (s *ClientsService) Update(ctx context.Context, id string, p Contact) (*Contact, error) {
	if id == "" {
		return nil, opEmptyID("Clients.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/clients/" + pathID(id), body: p, op: "Clients.Update"}); err != nil {
		return nil, err
	}
	if contacts, err := s.List(ctx); err == nil {
		for i := range contacts {
			if contacts[i].ID == id {
				return &contacts[i], nil
			}
		}
	}
	p.ID = id
	return &p, nil
}

// Delete deletes the client contact with the given id.
func (s *ClientsService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Clients.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/clients/" + pathID(id), op: "Clients.Delete"})
}

// FindByEmail returns the client contact with the given email (case-insensitive),
// or nil.
func (s *ClientsService) FindByEmail(ctx context.Context, email string) (*Contact, error) {
	contacts, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range contacts {
		if strings.EqualFold(contacts[i].Email, email) {
			return &contacts[i], nil
		}
	}
	return nil, nil
}
