package plg_backend_minio_keycloak

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/filestash/server/model"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"

	"github.com/minio/minio-go/v7"
	mcredentials "github.com/minio/minio-go/v7/pkg/credentials"
)

/**
 * Code for STS
 */

// Returns a base64 encoded random 32 byte string.
func randomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var (
	stsEndpoint    string
	configEndpoint string
	clientID       string
	clientSec      string
	clientScopes   string
	state          string
	config         oauth2.Config
)

// DiscoveryDoc - parses the output from openid-configuration
// for example http://localhost:8080/auth/realms/minio/.well-known/openid-configuration
type DiscoveryDoc struct {
	Issuer                           string   `json:"issuer,omitempty"`
	AuthEndpoint                     string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

func implicitFlowURL(c *oauth2.Config, state string) string {

	log.Printf("implicitFlowURL ClientID %s", c.ClientID)
	log.Printf("implicitFlowURL AuthEndpoint %s", c.Endpoint.AuthURL)
	log.Printf("implicitFlowURL RedirectURL %s", c.RedirectURL)

	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"id_token"},
		"response_mode": {"form_post"},
		"client_id":     {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	v.Set("state", state)
	v.Set("nonce", state)
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func parseDiscoveryDoc(ustr string) (DiscoveryDoc, error) {
	d := DiscoveryDoc{}
	req, err := http.NewRequest(http.MethodGet, ustr, nil)
	if err != nil {
		return d, err
	}
	clnt := http.Client{
		Transport: http.DefaultTransport,
	}
	resp, err := clnt.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, err
	}
	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&d); err != nil {
		return d, err
	}
	return d, nil
}

func (s MinioKeycloakBackend) OAuthURL() string {
	log.Println("Minio OAuthURL")
	log.Printf("Minio OAuthURL state %s", s.state)
	if clientSec != "" {
		log.Println(fmt.Sprintf("Minio OAuthURL AuthCodeURL, %s", config.AuthCodeURL(s.state)))
		return config.AuthCodeURL(s.state)
	} else {
		log.Println(fmt.Sprintf("Minio OAuthURL implicitFlowURL, %s", implicitFlowURL(s.oauth_config, s.state)))
		return implicitFlowURL(s.oauth_config, s.state)
	}
}

/**
 * Code for S3
 */

var MinioCache AppCache

type MinioKeycloakBackend struct {
	oauth_config *oauth2.Config
	client       *s3.S3
	config       *aws.Config
	params       map[string]string
	state        string
}

func init() {
	Backend.Register("minio", MinioKeycloakBackend{})
	MinioCache = NewAppCache(2, 1)
	log.Println("Minio init")

	Hooks.Register.HttpEndpoint(func(r *mux.Router, _ *App) error {
		r.HandleFunc("/miniotest", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}).Methods("GET")

		return nil
	})

	Hooks.Register.HttpEndpoint(func(r *mux.Router, app *App) error {
		r.HandleFunc("/minio",
			func(res http.ResponseWriter, req *http.Request) {
				SessionAuthenticate(*app, res, req)
			}).Methods("POST")
		return nil
	})

}

func SessionAuthenticate(app App, w http.ResponseWriter, r *http.Request) {
	log.Println("Minio callback")
	log.Printf("session::oauth 'SessionAuthenticate' %+v", app.Body)
	log.Printf("%s %s", r.Method, r.RequestURI)

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	app.Body["timestamp"] = time.Now().String()
	session := model.MapStringInterfaceToMapStringString(app.Body)
	session["path"] = EnforceDirectory(session["path"])

	backend, err := model.NewBackend(&app, session)
	if err != nil {
		Log.Debug("session::auth 'NewBackend' %+v", err)
		SendErrorResult(w, err)
		return
	}
	log.Printf("backend %+v", backend)

	ctx := context.Background()

	var getWebTokenExpiry func() (*mcredentials.WebIdentityToken, error)
	if clientSec == "" {
		getWebTokenExpiry = func() (*mcredentials.WebIdentityToken, error) {
			return &mcredentials.WebIdentityToken{
				Token: r.Form.Get("id_token"),
			}, nil
		}
	} else {
		getWebTokenExpiry = func() (*mcredentials.WebIdentityToken, error) {
			oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				return nil, err
			}
			if !oauth2Token.Valid() {
				return nil, errors.New("invalid token")
			}

			return &mcredentials.WebIdentityToken{
				Token:  oauth2Token.Extra("id_token").(string),
				Expiry: int(oauth2Token.Expiry.Sub(time.Now().UTC()).Seconds()),
			}, nil
		}
	}

	stsEndpoint := Config.Get("auth.minio.sts_endpoint").Default("http://10.40.0.206:9000").String()
	log.Printf("id_token %s", r.Form.Get("id_token"))
	log.Printf("getWebTokenExpiry %s", getWebTokenExpiry)

	sts, err := mcredentials.NewSTSWebIdentity(stsEndpoint, getWebTokenExpiry)
	if err != nil {
		log.Println(fmt.Errorf("Could not get STS credentials: %s", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("sts %s", sts)

	opts := &minio.Options{
		Creds:        sts,
		BucketLookup: minio.BucketLookupAuto,
	}
	log.Printf("host %v", opts)

	u, err := url.Parse(stsEndpoint)
	if err != nil {
		log.Println(fmt.Errorf("Failed to parse STS Endpoint: %s", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	log.Printf("host %s", u.Host)

	//clnt, err := minio.New(u.Host, opts)
	//if err != nil {
	//	log.Println(fmt.Errorf("Error while initializing Minio client, %s", err))
	//	return NewError(err.Error(), http.StatusBadRequest)
	//}
	//buckets, err := clnt.ListBuckets(r.Context())
	//if err != nil {
	//	log.Println(fmt.Errorf("Error while listing buckets, %s", err))
	//	return NewError(err.Error(), http.StatusBadRequest)
	//}
	//creds, _ := sts.Get()

	//bucketNames := []string{}
	//
	//for _, bucket := range buckets {
	//	log.Println(fmt.Sprintf("Bucket discovered: %s", bucket.Name))
	//	bucketNames = append(bucketNames, bucket.Name)
	//}
	//response := make(map[string]interface{})
	//response["credentials"] = creds
	//response["buckets"] = bucketNames
	//c, err := json.MarshalIndent(response, "", "\t")
	//if err != nil {
	//	return NewError(w, err.Error(), http.StatusInternalServerError)
	//}
}

func (s MinioKeycloakBackend) Init(params map[string]string, app *App) (IBackend, error) {
	log.Println("Minio Init")
	//if params["encryption_key"] != "" && len(params["encryption_key"]) != 32 {
	//	return nil, NewError(fmt.Sprintf("Encryption key needs to be 32 characters (current: %d)", len(params["encryption_key"])), 400)
	//}
	//
	//if params["region"] == "" {
	//	params["region"] = "us-east-2"
	//}

	// store parameters

	configEndpoint := Config.Get("auth.minio.config_endpoint").Default("http://10.40.0.206:8080/auth/realms/application/.well-known/openid-configuration").String()
	clientID := Config.Get("auth.minio.client_id").Default("minioclient").String()
	clientSec := Config.Get("auth.minio.client_secret").Default("").String()
	clientScopes := Config.Get("auth.minio.client_scope").Default("").String()

	ddoc, err := parseDiscoveryDoc(configEndpoint)
	if err != nil {
		return nil, NewError(fmt.Sprintf("Failed to parse OIDC discovery document %s", err), 400)
	}

	log.Printf("AuthEndpoint %s", ddoc.AuthEndpoint)

	scopes := ddoc.ScopesSupported
	if clientScopes != "" {
		scopes = strings.Split(clientScopes, ",")
	}

	localip := func() string { // https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go#23558495
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return ""
		}
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
		return ""
	}()

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSec,
		Endpoint: oauth2.Endpoint{
			AuthURL:  ddoc.AuthEndpoint,
			TokenURL: ddoc.TokenEndpoint,
		},
		RedirectURL: fmt.Sprintf("http://%s:%d/minio",
			Config.Get("general.host").Default(localip).String(), Config.Get("general.port").Int()),
		Scopes: scopes,
	}

	state := randomState()
	log.Printf("Init state %s", state)

	config2 := &aws.Config{
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.StaticProvider{Value: credentials.Value{
					AccessKeyID:     params["access_key_id"],
					SecretAccessKey: params["secret_access_key"],
					SessionToken:    params["session_token"],
				}},
				&credentials.EnvProvider{},
				&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(session.Must(session.NewSession()))},
			},
		),
		CredentialsChainVerboseErrors: aws.Bool(true),
		S3ForcePathStyle:              aws.Bool(true),
		Region:                        aws.String(params["region"]),
	}
	if params["endpoint"] != "" {
		config2.Endpoint = aws.String(params["endpoint"])
	}

	backend := &MinioKeycloakBackend{
		oauth_config: config,
		config:       config2,
		params:       params,
		client:       s3.New(session.New(config2)),
		state:        state,
	}
	return backend, nil
}

func (s MinioKeycloakBackend) LoginForm() Form {
	return Form{
		Elmnts: []FormElement{
			FormElement{
				Name:  "type",
				Type:  "hidden",
				Value: "minio",
			},
			FormElement{
				ReadOnly: true,
				Name:     "oauth2",
				Type:     "text",
				Value:    "/api/session/auth/minio",
			},
		},
	}
}

func (s MinioKeycloakBackend) Meta(path string) Metadata {
	if path == "/" {
		return Metadata{
			CanCreateFile: NewBool(false),
			CanRename:     NewBool(false),
			CanMove:       NewBool(false),
			CanUpload:     NewBool(false),
		}
	}
	return Metadata{}
}

func (s MinioKeycloakBackend) Ls(path string) (files []os.FileInfo, err error) {
	files = make([]os.FileInfo, 0)
	p := s.path(path)

	if p.bucket == "" {
		b, err := s.client.ListBuckets(&s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		for _, bucket := range b.Buckets {
			files = append(files, &File{
				FName:   *bucket.Name,
				FType:   "directory",
				FTime:   bucket.CreationDate.Unix(),
				CanMove: NewBool(false),
			})
		}
		return files, nil
	}
	client := s3.New(s.createSession(p.bucket))

	err = client.ListObjectsV2Pages(
		&s3.ListObjectsV2Input{
			Bucket:    aws.String(p.bucket),
			Prefix:    aws.String(p.path),
			Delimiter: aws.String("/"),
		},
		func(objs *s3.ListObjectsV2Output, lastPage bool) bool {
			for i, object := range objs.Contents {
				if i == 0 && *object.Key == p.path {
					continue
				}
				files = append(files, &File{
					FName: filepath.Base(*object.Key),
					FType: "file",
					FTime: object.LastModified.Unix(),
					FSize: *object.Size,
				})
			}
			for _, object := range objs.CommonPrefixes {
				files = append(files, &File{
					FName: filepath.Base(*object.Prefix),
					FType: "directory",
				})
			}
			return true
		})
	return files, err
}

func (s MinioKeycloakBackend) Cat(path string) (io.ReadCloser, error) {
	p := s.path(path)
	client := s3.New(s.createSession(p.bucket))

	input := &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.path),
	}
	if s.params["encryption_key"] != "" {
		input.SSECustomerAlgorithm = aws.String("AES256")
		input.SSECustomerKey = aws.String(s.params["encryption_key"])
	}
	obj, err := client.GetObject(input)
	if err != nil {
		awsErr, ok := err.(awserr.Error)
		if ok == false {
			return nil, err
		}
		if awsErr.Code() == "InvalidRequest" && strings.Contains(awsErr.Message(), "encryption") {
			input.SSECustomerAlgorithm = nil
			input.SSECustomerKey = nil
			obj, err = client.GetObject(input)
			return obj.Body, err
		} else if awsErr.Code() == "InvalidArgument" && strings.Contains(awsErr.Message(), "secret key was invalid") {
			return nil, NewError("This file is encrypted file, you need the correct key!", 400)
		} else if awsErr.Code() == "AccessDenied" {
			return nil, ErrNotAllowed
		}
		return nil, err
	}

	return obj.Body, nil
}

func (s MinioKeycloakBackend) Mkdir(path string) error {
	p := s.path(path)
	client := s3.New(s.createSession(p.bucket))

	if p.path == "" {
		_, err := client.CreateBucket(&s3.CreateBucketInput{
			Bucket: aws.String(path),
		})
		return err
	}
	_, err := client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.path),
	})
	return err
}

func (s MinioKeycloakBackend) Rm(path string) error {
	p := s.path(path)
	client := s3.New(s.createSession(p.bucket))
	if p.bucket == "" {
		return ErrNotFound
	} else if strings.HasSuffix(path, "/") == false {
		_, err := client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    aws.String(p.path),
		})
		return err
	}

	objs, err := client.ListObjects(&s3.ListObjectsInput{
		Bucket:    aws.String(p.bucket),
		Prefix:    aws.String(p.path),
		Delimiter: aws.String("/"),
	})
	if err != nil {
		return err
	}
	for _, obj := range objs.Contents {
		_, err := client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    obj.Key,
		})
		if err != nil {
			return err
		}
	}
	for _, pref := range objs.CommonPrefixes {
		s.Rm("/" + p.bucket + "/" + *pref.Prefix)
		_, err := client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    pref.Prefix,
		})
		if err != nil {
			return err
		}
	}

	if p.path == "" {
		_, err := client.DeleteBucket(&s3.DeleteBucketInput{
			Bucket: aws.String(p.bucket),
		})
		return err
	}
	_, err = client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.path),
	})
	return err
}

func (s MinioKeycloakBackend) Mv(from string, to string) error {
	f := s.path(from)
	t := s.path(to)
	client := s3.New(s.createSession(f.bucket))

	if f.path == "" {
		// Rename bucket
		return ErrNotImplemented
	} else if strings.HasSuffix(from, "/") == false {
		// Move Single file
		input := &s3.CopyObjectInput{
			Bucket:     aws.String(t.bucket),
			CopySource: aws.String(f.bucket + "/" + f.path),
			Key:        aws.String(t.path),
		}
		if s.params["encryption_key"] != "" {
			input.CopySourceSSECustomerAlgorithm = aws.String("AES256")
			input.CopySourceSSECustomerKey = aws.String(s.params["encryption_key"])
			input.SSECustomerAlgorithm = aws.String("AES256")
			input.SSECustomerKey = aws.String(s.params["encryption_key"])
		}

		_, err := client.CopyObject(input)
		if err != nil {
			return err
		}
		_, err = client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(f.bucket),
			Key:    aws.String(f.path),
		})
		return err
	}

	// Move recursively files and subfolders
	err := client.ListObjectsV2Pages(
		&s3.ListObjectsV2Input{
			Bucket:    aws.String(f.bucket),
			Prefix:    aws.String(f.path),
			Delimiter: aws.String("/"),
		},
		func(objs *s3.ListObjectsV2Output, lastPage bool) bool {
			for _, obj := range objs.Contents {
				from := f.bucket + "/" + *obj.Key
				toKey := t.path + strings.TrimPrefix(*obj.Key, f.path)
				input := &s3.CopyObjectInput{
					CopySource: aws.String(from),
					Bucket:     aws.String(t.bucket),
					Key:        aws.String(toKey),
				}
				if s.params["encryption_key"] != "" {
					input.CopySourceSSECustomerAlgorithm = aws.String("AES256")
					input.CopySourceSSECustomerKey = aws.String(s.params["encryption_key"])
					input.SSECustomerAlgorithm = aws.String("AES256")
					input.SSECustomerKey = aws.String(s.params["encryption_key"])
				}

				Log.Debug("CopyObject(%s, %s):", from, f.bucket+"/"+toKey)
				_, err := client.CopyObject(input)
				if err != nil {
					Log.Error("CopyObject from: %s to: %s",
						f.bucket+"/"+*obj.Key,
						t.bucket+"/"+t.path+*obj.Key,
						err)
					return false
				}

				Log.Debug("DeleteObject(%s):", f.bucket+"/"+*obj.Key)
				_, err = client.DeleteObject(&s3.DeleteObjectInput{
					Bucket: aws.String(f.bucket),
					Key:    obj.Key,
				})
				if err != nil {
					Log.Error("DeleteObject failed: %s", *obj.Key, err)
					return false
				}
			}
			for _, pref := range objs.CommonPrefixes {
				from := "/" + f.bucket + "/" + *pref.Prefix
				to := "/" + t.bucket + "/" + t.path + "/" + strings.TrimPrefix(*pref.Prefix, f.path)
				Log.Debug("Mv(%s, %s):", from, to)
				err := s.Mv(from, to)
				if err != nil {
					Log.Error("Mv(%s, %s) failed:", from, to, err)
					return false
				}
			}
			return true
		})
	if err != nil {
		Log.Error("ListObjectsV2Pages failed:", err)
	}
	return err
}

func (s MinioKeycloakBackend) Touch(path string) error {
	p := s.path(path)
	client := s3.New(s.createSession(p.bucket))

	if p.bucket == "" {
		return ErrNotValid
	}

	input := &s3.PutObjectInput{
		Body:          strings.NewReader(""),
		ContentLength: aws.Int64(0),
		Bucket:        aws.String(p.bucket),
		Key:           aws.String(p.path),
	}
	if s.params["encryption_key"] != "" {
		input.SSECustomerAlgorithm = aws.String("AES256")
		input.SSECustomerKey = aws.String(s.params["encryption_key"])
	}
	_, err := client.PutObject(input)
	return err
}

func (s MinioKeycloakBackend) Save(path string, file io.Reader) error {
	p := s.path(path)

	if p.bucket == "" {
		return ErrNotValid
	}
	uploader := s3manager.NewUploader(s.createSession(path))
	input := s3manager.UploadInput{
		Body:   file,
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.path),
	}
	if s.params["encryption_key"] != "" {
		input.SSECustomerAlgorithm = aws.String("AES256")
		input.SSECustomerKey = aws.String(s.params["encryption_key"])
	}
	_, err := uploader.Upload(&input)
	return err
}

func (s MinioKeycloakBackend) createSession(bucket string) *session.Session {
	params := s.params
	params["bucket"] = bucket
	c := MinioCache.Get(params)
	if c == nil {
		res, err := s.client.GetBucketLocation(&s3.GetBucketLocationInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.config.Region = aws.String("us-east-1")
		} else {
			if res.LocationConstraint == nil {
				s.config.Region = aws.String("us-east-1")
			} else {
				s.config.Region = res.LocationConstraint
			}
		}
		MinioCache.Set(params, s.config.Region)
	} else {
		s.config.Region = c.(*string)
	}

	sess := session.New(s.config)
	return sess
}

type S3Path struct {
	bucket string
	path   string
}

func (s MinioKeycloakBackend) path(p string) S3Path {
	sp := strings.Split(p, "/")
	bucket := ""
	if len(sp) > 1 {
		bucket = sp[1]
	}
	path := ""
	if len(sp) > 2 {
		path = strings.Join(sp[2:], "/")
	}

	return S3Path{
		bucket,
		path,
	}
}
