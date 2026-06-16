package pwndoc

import (
	"context"
	"fmt"
	"strings"
)

// resolveCompany finds a company by case-insensitive name, creating it if
// missing, and returns a CompanyRef wired by id.
func (c *Client) resolveCompany(ctx context.Context, name string) (*CompanyRef, error) {
	companies, err := c.Companies.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range companies {
		if strings.EqualFold(companies[i].Name, name) {
			return &CompanyRef{ID: companies[i].ID, Name: companies[i].Name}, nil
		}
	}
	created, err := c.Companies.Create(ctx, Company{Name: name})
	if err != nil {
		return nil, fmt.Errorf("pwndoc: resolveCompany %q: %w", name, err)
	}
	return &CompanyRef{ID: created.ID, Name: created.Name}, nil
}

// resolveContact finds a client contact by email, creating it (optionally under
// a company) if missing, and returns the full *Contact wired by id.
func (c *Client) resolveContact(ctx context.Context, email, firstname, lastname string, company *CompanyRef) (*Contact, error) {
	contacts, err := c.Clients.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range contacts {
		if strings.EqualFold(contacts[i].Email, email) {
			return &contacts[i], nil
		}
	}
	created, err := c.Clients.Create(ctx, Contact{
		Email: email, Firstname: firstname, Lastname: lastname, Company: company,
	})
	if err != nil {
		return nil, fmt.Errorf("pwndoc: resolveContact %q: %w", email, err)
	}
	return created, nil
}

// resolveUsers maps usernames (or emails) to full User records. Unknown names
// are reported as an error so callers learn of typos.
func (c *Client) resolveUsers(ctx context.Context, names []string) ([]User, error) {
	if len(names) == 0 {
		return nil, nil
	}
	all, err := c.Users.List(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string]*User, len(all)*2)
	for i := range all {
		index[strings.ToLower(all[i].Username)] = &all[i]
		if all[i].Email != "" {
			index[strings.ToLower(all[i].Email)] = &all[i]
		}
	}
	out := make([]User, 0, len(names))
	var missing []string
	for _, n := range names {
		if u, ok := index[strings.ToLower(n)]; ok {
			out = append(out, *u)
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("pwndoc: unknown user(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}
