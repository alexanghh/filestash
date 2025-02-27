package plg_backend_s3sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	. "github.com/mickael-kerjean/filestash/server/common"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

var (
	OpenIDAuthenticationEndpoint  string
	OpenIDTokenEndpoint           string
	OpenIDUserInfoEndpoint        string
	SECRET_KEY_DERIVATE_FOR_NONCE string
	VALID_SESSION_TIMEOUT         int
)

func init() {
	SECRET_KEY_DERIVATE_FOR_NONCE = Hash("OPENID_NONCE_"+SECRET_KEY, len(SECRET_KEY))
	VALID_SESSION_TIMEOUT = 3600 * 12 // 1 working day
	openIDConfig()
	openIDClientID()
	openIDClientSecret()
	openIDClientScopes()
	openIDRedirectHost()
}

var openIDConfig = func() string {
	return Config.Get("s3sts.openid.configuration").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = "http://127.0.0.1:8080/auth/realms/filestash/.well-known/openid-configuration"
		f.Name = "configuration"
		f.Type = "text"
		f.Placeholder = "Configuration URL of openid"
		return f
	}).String()
}

var openIDClientID = func() string {
	return Config.Get("s3sts.openid.client_id").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = "filestash"
		f.Name = "client_id"
		f.Type = "text"
		f.Placeholder = "client_id"
		return f
	}).String()
}

var openIDClientSecret = func() string {
	return Config.Get("s3sts.openid.client_secret").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = ""
		f.Name = "client_secret"
		f.Type = "password"
		f.Placeholder = "client_secret"
		return f
	}).String()
}

var openIDClientScopes = func() string {
	return Config.Get("s3sts.openid.scopes").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = "openid"
		f.Name = "scopes"
		f.Type = "text"
		f.Placeholder = "comma separated list of scopes"
		return f
	}).String()
}

var openIDRedirectHost = func() string {
	return Config.Get("s3sts.openid.redirect_host").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = ""
		f.Name = "redirect_host"
		f.Type = "text"
		f.Placeholder = "hostname for redirect url"
		return f
	}).String()
}

func OpenID() *oauth2.Config {
	hostname := openIDRedirectHost()
	if hostname == "" {
		hostname = Config.Get("general.host").String()
	}

	return &oauth2.Config{
		RedirectURL:  fmt.Sprintf("https://%s/login", hostname),
		ClientID:     openIDClientID(),
		ClientSecret: openIDClientSecret(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  OpenIDAuthenticationEndpoint,
			TokenURL: OpenIDTokenEndpoint,
		},
		Scopes: strings.Split(openIDClientScopes(), ","),
	}
}

func OpenIDGetURL() string {
	req, err := http.NewRequest("GET", openIDConfig(), nil)
	if err != nil {
		Log.Error("oauth2::http::new %+v", err)
		return OpenID().AuthCodeURL("s3sts")
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		Log.Error("oauth2::http::do %+v", err)
		return OpenID().AuthCodeURL("s3sts")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		Log.Error("oauth2::http::status %d", resp.StatusCode)
		return OpenID().AuthCodeURL("s3sts")
	}
	dec := json.NewDecoder(resp.Body)
	d := struct {
		AuthEndpoint     string `json:"authorization_endpoint,omitempty"`
		TokenEndpoint    string `json:"token_endpoint,omitempty"`
		UserInfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	}{}
	if err = dec.Decode(&d); err != nil {
		Log.Error("oauth2::http::decode %+v", err)
		return OpenID().AuthCodeURL("s3sts")
	}
	OpenIDAuthenticationEndpoint = d.AuthEndpoint
	OpenIDTokenEndpoint = d.TokenEndpoint
	OpenIDUserInfoEndpoint = d.UserInfoEndpoint
	url := OpenID().AuthCodeURL("s3sts") + "&nonce=" + OpenIDCreateNonce()
	return url
}

func OAuth2Authenticate(code string) (*oauth2.Token, error) {
	Log.Info("oauth2::authenticate")
	token, err := OpenID().Exchange(context.Background(), code)
	if err != nil {
		Log.Warning("oauth2::error - couldn't exchange code for token: %+v", err)
		Log.Debug("oauth2::error - code: %s", code)
		return nil, ErrNotValid
	}
	if token.Valid() == false {
		Log.Warning("oauth2::error - token is not valid")
		Log.Debug("oauth2::error - code: %s, token %+v", code, token)
		return nil, ErrNotValid
	}
	return token, nil
}

func OAuth2RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	Log.Info("oauth2::refresh")
	if token.RefreshToken != "" {
		OpenIDGetURL()
		updatedToken, err := OpenID().TokenSource(context.TODO(), token).Token()
		if err != nil {
			Log.Error("oauth2::OAuth2RefreshToken %+v", err)
			Log.Debug("oauth2::OAuth2RefreshToken - token %+v", token)
			return nil, ErrAuthenticationFailed
		}
		token = updatedToken
	}
	return token, nil
}

func OpenIDCreateNonce() string {
	nonce, _ := EncryptString(SECRET_KEY_DERIVATE_FOR_NONCE, time.Now().UTC().String())
	return nonce
}

func OpenIDVerifyToken(token string) error {
	// access_token in openid is a JWT token. We will be extracting the nonce from the
	// token payload and make sure the nonce was created not too long ago
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 { // [0] header, [1] payload, [2] signature
		return ErrAuthenticationFailed
	}
	p, err := base64.RawStdEncoding.DecodeString(chunks[1])
	if err != nil {
		return ErrAuthenticationFailed
	}
	payload := struct {
		Nonce string `json:"nonce"`
	}{""}
	err = json.Unmarshal([]byte(p), &payload)
	if err != nil {
		return ErrAuthenticationFailed
	} else if len(payload.Nonce) < 5 {
		return ErrAuthenticationFailed
	}

	d, err := DecryptString(SECRET_KEY_DERIVATE_FOR_NONCE, payload.Nonce)
	if err != nil {
		return ErrAuthenticationFailed
	}
	t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", d)
	if err != nil {
		return ErrAuthenticationFailed
	}
	if int(time.Since(t).Seconds()) > VALID_SESSION_TIMEOUT {
		return NewError("Unauthorized", 401) // trigger login redirection
	}
	return nil
}
