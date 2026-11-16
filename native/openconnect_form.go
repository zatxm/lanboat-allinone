package native

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

type OpenConnectAuthOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}
type OpenConnectAuthField struct {
	Name    string                  `json:"name"`
	Type    string                  `json:"type"`
	Label   string                  `json:"label"`
	Value   string                  `json:"value,omitempty"`
	Options []OpenConnectAuthOption `json:"options,omitempty"`
}
type OpenConnectAuthForm struct {
	Endpoint string                 `json:"endpoint"`
	URL      string                 `json:"url"`
	ID       string                 `json:"id"`
	Title    string                 `json:"title,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Fields   []OpenConnectAuthField `json:"fields"`
	SSO      *OpenConnectSSO        `json:"sso,omitempty"`
	HostScan *OpenConnectHostScan   `json:"host_scan,omitempty"`
}

// Handlers must honor ctx cancellation; answers contain only the advertised editable fields.
type OpenConnectAuthHandler func(context.Context, OpenConnectAuthForm) (map[string]string, error)
type ocAuthHandlerKey struct{}

func WithOpenConnectAuth(ctx context.Context, handler OpenConnectAuthHandler) context.Context {
	return context.WithValue(ctx, ocAuthHandlerKey{}, handler)
}
func (r *Runtime) SetOpenConnectAuthHandler(handler OpenConnectAuthHandler) {
	if handler == nil {
		r.ocAuthHandler.Store(nil)
	} else {
		r.ocAuthHandler.Store(&handler)
	}
}

type OpenConnectAuthRequiredError struct{ Form OpenConnectAuthForm }

func (*OpenConnectAuthRequiredError) Error() string {
	return "OpenConnect authentication requires user interaction"
}

// AuthenticateOpenConnect establishes the VPN before local applications issue proxy requests.
func (r *Runtime) AuthenticateOpenConnect(ctx context.Context, tag string) error {
	c := r.ocClients[tag]
	if c == nil {
		return fmt.Errorf("unknown OpenConnect outbound %q", tag)
	}
	_, err := c.session(ctx)
	return err
}

func (o OpenConnectOptions) authDuration() time.Duration {
	d, _ := optionDuration(o.AuthTimeout, 5*time.Minute)
	return d
}
func ocFieldName(s string) bool {
	if len(s) == 0 || len(s) > 128 || s == "xmlns" {
		return false
	}
	for i, b := range []byte(s) {
		if b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || i > 0 && (b >= '0' && b <= '9' || b == '-' || b == '.') {
			continue
		}
		return false
	}
	return true
}
func (c *ocClient) answer(ctx context.Context, u *url.URL, auth *ocAuth, sent map[string]bool) (ocXML, error) {
	f := auth.Form
	if len(f.Inputs)+len(f.Selects) > 128 || len(auth.ID) > 128 {
		return ocXML{}, errors.New("OpenConnect authentication form exceeds limits")
	}
	form := OpenConnectAuthForm{Endpoint: c.o.Tag, URL: u.String(), ID: auth.ID, Title: auth.Title, Message: auth.Message, Error: auth.Error}
	sso, err := ocSSOForm(u, auth)
	if err != nil {
		return ocXML{}, err
	}
	form.SSO = sso
	if sso != nil && c.o.DisableExternalAuth {
		return ocXML{}, errors.New("OpenConnect browser authentication is disabled")
	}
	values := map[string]string{}
	editable := map[string]bool{}
	needs := false
	add := func(name string) error {
		if !ocFieldName(name) {
			return errors.New("invalid OpenConnect form field")
		}
		if _, ok := values[name]; ok {
			return errors.New("duplicate OpenConnect form field")
		}
		values[name] = ""
		return nil
	}
	for _, field := range f.Inputs {
		if field.Type == "" {
			field.Type = "text"
		}
		if field.Type == "submit" {
			continue
		}
		if err := add(field.Name); err != nil {
			return ocXML{}, err
		}
		if field.Type == "hidden" {
			values[field.Name] = field.Value
			continue
		}
		if field.Type != "text" && field.Type != "password" && field.Type != "sso" {
			return ocXML{}, errors.New("unsupported OpenConnect form control")
		}
		editable[field.Name] = true
		if field.Type == "sso" {
			if sso == nil {
				return ocXML{}, errors.New("OpenConnect SSO form is missing browser metadata")
			}
			needs = true
			form.Fields = append(form.Fields, OpenConnectAuthField{Name: field.Name, Type: "sso", Label: field.Label})
			continue
		}
		v, ok := c.o.AuthForm[auth.ID][field.Name]
		promote := false
		if e := c.o.ocEndpoint; e != nil {
			if value, found, ask := e.field(auth.ID, field.Name); found {
				v, ok, promote = value, true, ask
			}
		}
		key := auth.ID + "\x00" + field.Name
		if !ok && field.Name == "username" {
			v, ok = c.o.Username, c.o.Username != ""
		}
		if !ok && field.Name == "password" && field.Type == "password" {
			v, ok = c.o.Password, c.o.Password != ""
			if sent["@password"] {
				ok = false
			}
		}
		if promote || !ok || sent[key] || auth.Error != "" || auth.ID == "failure" {
			needs = true
			v = ""
		}
		values[field.Name] = v
		view := OpenConnectAuthField{Name: field.Name, Type: field.Type, Label: field.Label}
		if field.Type == "text" && field.Name != "password" {
			view.Value = v
		}
		form.Fields = append(form.Fields, view)
	}
	for _, field := range f.Selects {
		if err := add(field.Name); err != nil {
			return ocXML{}, err
		}
		if len(field.Options) == 0 || len(field.Options) > 128 {
			return ocXML{}, errors.New("invalid OpenConnect authentication choices")
		}
		v, configured := c.o.AuthForm[auth.ID][field.Name]
		if field.Name == "group_list" && c.o.Group != "" {
			v, configured = c.o.Group, true
		}
		promote := false
		if e := c.o.ocEndpoint; e != nil {
			if value, found, ask := e.field(auth.ID, field.Name); found {
				v, configured, promote = value, !ask, ask
			}
		}
		view := OpenConnectAuthField{Name: field.Name, Type: "select", Label: field.Label}
		if !configured {
			v = field.Options[0].Value
			for _, o := range field.Options {
				if o.Selected == "true" || o.Selected == "selected" {
					v = o.Value
				}
			}
		}
		for _, o := range field.Options {
			view.Options = append(view.Options, OpenConnectAuthOption{Value: o.Value, Label: o.Text})
		}
		if !slices.ContainsFunc(view.Options, func(o OpenConnectAuthOption) bool { return o.Value == v }) {
			return ocXML{}, errors.New("OpenConnect authentication choice is unavailable")
		}
		editable[field.Name] = true
		values[field.Name] = v
		view.Value = v
		form.Fields = append(form.Fields, view)
		if promote || field.Name != "group_list" && !configured || auth.Error != "" || auth.ID == "failure" {
			needs = true
		}
	}
	if needs {
		handler, _ := ctx.Value(ocAuthHandlerKey{}).(OpenConnectAuthHandler)
		if handler == nil {
			if h := c.r.ocAuthHandler.Load(); h != nil {
				handler = *h
			}
		}
		if handler == nil {
			return ocXML{}, &OpenConnectAuthRequiredError{Form: form}
		}
		var answers map[string]string
		var err error
		if sso != nil && sso.Mode == "external" {
			answers, err = c.externalSSO(ctx, form, handler)
		} else {
			answers, err = handler(ctx, form)
		}
		if err != nil {
			return ocXML{}, err
		}
		if err := ctx.Err(); err != nil {
			return ocXML{}, err
		}
		for name, v := range answers {
			if !editable[name] {
				return ocXML{}, errors.New("OpenConnect answer contains an unrequested or hidden field")
			}
			values[name] = v
		}
	}
	message := ocXML{Client: "vpn", Type: "auth-reply", Aggregate: "2", Agent: &ocAgentVersion{Who: "vpn", Value: Version}, Auth: &ocAuth{}}
	c.endpointIdentity(&message)
	for _, field := range form.Fields {
		v := values[field.Name]
		if len(v) > 8192 || (field.Type == "password" || field.Type == "sso" || field.Name == "username") && v == "" || strings.ContainsRune(v, 0) {
			return ocXML{}, errors.New("missing or oversized OpenConnect authentication answer")
		}
		if field.Type == "select" && !slices.ContainsFunc(field.Options, func(o OpenConnectAuthOption) bool { return o.Value == v }) {
			return ocXML{}, errors.New("invalid OpenConnect authentication answer choice")
		}
		if field.Type == "sso" && !ocValidCookie(v) {
			return ocXML{}, errors.New("invalid OpenConnect browser token")
		}
		if field.Name == "group_list" {
			message.Group = v
		}
		sent[auth.ID+"\x00"+field.Name] = true
		if field.Name == "password" {
			sent["@password"] = true
		}
	}
	// Preserve wire order and opaque state, without allowing the UI to rewrite hidden fields.
	for _, field := range f.Inputs {
		if field.Type != "submit" {
			message.Auth.Fields = append(message.Auth.Fields, ocField{XMLName: xml.Name{Local: field.Name}, Value: values[field.Name]})
		}
	}
	for _, field := range f.Selects {
		message.Auth.Fields = append(message.Auth.Fields, ocField{XMLName: xml.Name{Local: field.Name}, Value: values[field.Name]})
	}
	if b, err := ocMarshal(message); err != nil || len(b) > 65536 {
		return ocXML{}, errors.New("OpenConnect authentication answer exceeds limits")
	}
	return message, nil
}

func (o OpenConnectOptions) validateAuth() error {
	if o.AuthTimeout != "" {
		d, e := time.ParseDuration(o.AuthTimeout)
		if e != nil || d < time.Second || d > 30*time.Minute {
			return errors.New("OpenConnect auth_timeout must be1s-30m")
		}
	}
	if len(o.AuthForm) > 32 {
		return errors.New("OpenConnect auth_form exceeds32 forms")
	}
	n := 0
	for id, fields := range o.AuthForm {
		if len(id) > 128 || len(fields) > 128 {
			return errors.New("invalid OpenConnect auth_form")
		}
		for name, v := range fields {
			n += len(v)
			if !ocFieldName(name) || len(v) > 8192 || n > 65536 || strings.ContainsRune(v, 0) {
				return errors.New("invalid OpenConnect authentication entry")
			}
		}
	}
	return nil
}
