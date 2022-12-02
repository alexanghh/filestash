package plg_authorisation_readonly

import (
	. "github.com/mickael-kerjean/filestash/server/common"
)

func init() {
	if plugin_enable := Config.Get("features.readonly.enable").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = false
		f.Name = "enable"
		f.Type = "boolean"
		f.Target = []string{}
		f.Description = "Enable/Disable read only mode. This setting requires a restart to come into effect."
		f.Placeholder = "Default: false"
		return f
	}).Bool(); plugin_enable == false {
		return
	}
	Hooks.Register.AuthorisationMiddleware(AuthM{})
}

type AuthM struct{}

func (this AuthM) Ls(ctx *App, path string) error {
	return nil
}

func (this AuthM) Cat(ctx *App, path string) error {
	return nil
}

func (this AuthM) Mkdir(ctx *App, path string) error {
	return ErrNotAllowed
}

func (this AuthM) Rm(ctx *App, path string) error {
	return ErrNotAllowed
}

func (this AuthM) Mv(ctx *App, from string, to string) error {
	return ErrNotAllowed
}

func (this AuthM) Save(ctx *App, path string) error {
	return ErrNotAllowed
}

func (this AuthM) Touch(ctx *App, path string) error {
	return ErrNotAllowed
}
