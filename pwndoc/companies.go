package pwndoc

import (
	"context"
	"net/http"
	"strings"
)

// Company represents a company in pwndoc.
type Company struct {
	ID        string `json:"_id,omitempty"`
	Name      string `json:"name"`
	ShortName string `json:"shortName,omitempty"`
	Logo      string `json:"logo,omitempty"` // base64 data URI
}

// CompaniesService manages companies.
type CompaniesService struct{ c *Client }

// List returns all companies.
func (s *CompaniesService) List(ctx context.Context) ([]Company, error) {
	return call[[]Company](ctx, s.c, apiReq{method: http.MethodGet, path: "/companies", op: "Companies.List"})
}

// Create creates a company. Name is required.
func (s *CompaniesService) Create(ctx context.Context, p Company) (*Company, error) {
	out, err := call[Company](ctx, s.c, apiReq{method: http.MethodPost, path: "/companies", body: p, op: "Companies.Create"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Update updates the company with the given id and returns the updated record.
func (s *CompaniesService) Update(ctx context.Context, id string, p Company) (*Company, error) {
	if id == "" {
		return nil, opEmptyID("Companies.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/companies/" + pathID(id), body: p, op: "Companies.Update"}); err != nil {
		return nil, err
	}
	p.ID = id
	return &p, nil
}

// Delete deletes the company with the given id.
func (s *CompaniesService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Companies.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/companies/" + pathID(id), op: "Companies.Delete"})
}

// FindByName returns the company whose name matches (case-insensitively), or nil.
func (s *CompaniesService) FindByName(ctx context.Context, name string) (*Company, error) {
	companies, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range companies {
		if strings.EqualFold(companies[i].Name, name) {
			return &companies[i], nil
		}
	}
	return nil, nil
}

// EnsureByName returns the named company, creating it if it does not exist.
func (s *CompaniesService) EnsureByName(ctx context.Context, name string) (*Company, error) {
	existing, err := s.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}
	return s.Create(ctx, Company{Name: name})
}
