package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func GetPath(subpath string) string {
	return subpath
}

func (b *backend) pathList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	path := req.Path

	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	entries, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("read failed: {{err}}", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}
	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %s", err)
	}

	// Generate the response
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func constructPath(pathAr []string) string {
	path := ""

	for pos, pathObject := range pathAr {
		path += pathObject
		if pos < len(pathAr)-1 {
			path += "/"
		}
	}

	return path
}

func stringsToUpper(s []string) []string {
	for i := range s {
		s[i] = strings.ToUpper(s[i])
	}
	return s
}

func sliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}