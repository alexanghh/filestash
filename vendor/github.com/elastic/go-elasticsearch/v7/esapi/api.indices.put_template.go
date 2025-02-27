// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// Code generated from specification version 7.17.0: DO NOT EDIT

package esapi

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func newIndicesPutTemplateFunc(t Transport) IndicesPutTemplate {
	return func(name string, body io.Reader, o ...func(*IndicesPutTemplateRequest)) (*Response, error) {
		var r = IndicesPutTemplateRequest{Name: name, Body: body}
		for _, f := range o {
			f(&r)
		}
		return r.Do(r.ctx, t)
	}
}

// ----- API Definition -------------------------------------------------------

// IndicesPutTemplate creates or updates an index template.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-templates.html.
//
type IndicesPutTemplate func(name string, body io.Reader, o ...func(*IndicesPutTemplateRequest)) (*Response, error)

// IndicesPutTemplateRequest configures the Indices Put Template API request.
//
type IndicesPutTemplateRequest struct {
	Body io.Reader

	Name string

	Create          *bool
	IncludeTypeName *bool
	MasterTimeout   time.Duration
	Order           *int

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context
}

// Do executes the request and returns response or error.
//
func (r IndicesPutTemplateRequest) Do(ctx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
	)

	method = "PUT"

	path.Grow(1 + len("_template") + 1 + len(r.Name))
	path.WriteString("/")
	path.WriteString("_template")
	path.WriteString("/")
	path.WriteString(r.Name)

	params = make(map[string]string)

	if r.Create != nil {
		params["create"] = strconv.FormatBool(*r.Create)
	}

	if r.IncludeTypeName != nil {
		params["include_type_name"] = strconv.FormatBool(*r.IncludeTypeName)
	}

	if r.MasterTimeout != 0 {
		params["master_timeout"] = formatDuration(r.MasterTimeout)
	}

	if r.Order != nil {
		params["order"] = strconv.FormatInt(int64(*r.Order), 10)
	}

	if r.Pretty {
		params["pretty"] = "true"
	}

	if r.Human {
		params["human"] = "true"
	}

	if r.ErrorTrace {
		params["error_trace"] = "true"
	}

	if len(r.FilterPath) > 0 {
		params["filter_path"] = strings.Join(r.FilterPath, ",")
	}

	req, err := newRequest(method, path.String(), r.Body)
	if err != nil {
		return nil, err
	}

	if len(params) > 0 {
		q := req.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	if r.Body != nil {
		req.Header[headerContentType] = headerContentTypeJSON
	}

	if len(r.Header) > 0 {
		if len(req.Header) == 0 {
			req.Header = r.Header
		} else {
			for k, vv := range r.Header {
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}
		}
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	res, err := transport.Perform(req)
	if err != nil {
		return nil, err
	}

	response := Response{
		StatusCode: res.StatusCode,
		Body:       res.Body,
		Header:     res.Header,
	}

	return &response, nil
}

// WithContext sets the request context.
//
func (f IndicesPutTemplate) WithContext(v context.Context) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.ctx = v
	}
}

// WithCreate - whether the index template should only be added if new or can also replace an existing one.
//
func (f IndicesPutTemplate) WithCreate(v bool) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.Create = &v
	}
}

// WithIncludeTypeName - whether a type should be returned in the body of the mappings..
//
func (f IndicesPutTemplate) WithIncludeTypeName(v bool) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.IncludeTypeName = &v
	}
}

// WithMasterTimeout - specify timeout for connection to master.
//
func (f IndicesPutTemplate) WithMasterTimeout(v time.Duration) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.MasterTimeout = v
	}
}

// WithOrder - the order for this template when merging multiple matching ones (higher numbers are merged later, overriding the lower numbers).
//
func (f IndicesPutTemplate) WithOrder(v int) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.Order = &v
	}
}

// WithPretty makes the response body pretty-printed.
//
func (f IndicesPutTemplate) WithPretty() func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
//
func (f IndicesPutTemplate) WithHuman() func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
//
func (f IndicesPutTemplate) WithErrorTrace() func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
//
func (f IndicesPutTemplate) WithFilterPath(v ...string) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
//
func (f IndicesPutTemplate) WithHeader(h map[string]string) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
//
func (f IndicesPutTemplate) WithOpaqueID(s string) func(*IndicesPutTemplateRequest) {
	return func(r *IndicesPutTemplateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
