package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAttributes(b *backend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: GetPath("authorityattributes/" + framework.GenericNameRegex("authority_name")),

			Fields: map[string]*framework.FieldSchema{
				"authority_name": {
					Type:        framework.TypeString,
					Description: "[Required] The authority to which the derived attributes correspond to",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getAuthorityAttrs,
				logical.CreateOperation: b.getAuthorityAttrs,
			},
		},
		{
			Pattern: GetPath("authorityattributes/" + framework.GenericNameRegex("authority_name") + "/" + framework.GenericNameRegex("attribute_name")),

			Fields: map[string]*framework.FieldSchema{
				"authority_name": {
					Type:        framework.TypeString,
					Description: "[Required] The authority to which the derived attribute corresponds to",
					Required:    true,
				},
				"attribute_name": {
					Type:        framework.TypeString,
					Description: "[Required] The attribute's name",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getDistinctAuthorityAttr,
				logical.CreateOperation: b.getDistinctAuthorityAttr,
			},
		},
		{
			Pattern: GetPath("common-attributes/"),

			Fields: map[string]*framework.FieldSchema{
				"attribute_type": {
					Type:        framework.TypeString,
					Description: "[Required] The desired type of the attributes (Accepts 2 types: `systemattributes` for System Attributes and `commonattributes` for Common Attributes)",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getCommonAttrs,
				logical.CreateOperation: b.getCommonAttrs,
			},
		},
		{
			Pattern: GetPath("common-attributes/" + framework.GenericNameRegex("attribute_name")),

			Fields: map[string]*framework.FieldSchema{
				"attribute_type": {
					Type:        framework.TypeString,
					Description: "[Required] The type of the attribute (Accepts 2 types: `systemattributes` for System Attributes and `commonattributes` for Common Attributes)",
					Required:    true,
				},
				"attribute_name": {
					Type:        framework.TypeString,
					Description: "[Required] The name of the desired attribute",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getDistinctCommonAttr,
				logical.CreateOperation: b.getDistinctCommonAttr,
			},
		},
	}
}

func (b *backend) getDistinctAuthorityAttr(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority_name := data.Get("authority_name").(string)
	attribute_name := strings.ToUpper(data.Get("attribute_name").(string))

	path := AUTHORITY_PATH + "/" + authority_name

	alphai, yi, err := b.getKeyData(ctx, req, path, attribute_name, false)
	if err != nil {
		return nil, fmt.Errorf("existence check failed: %s", err)
	}

	if alphai == nil || yi == nil {
		return logical.ErrorResponse("An attribute with the identifier %s does not exist for the authority %s", attribute_name, authority_name), nil
	}

	var publishedDataResponse = struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}{
		Alphai: alphai.String(),
		Yi:     yi.String(),
	}

	return &logical.Response{
		Data: map[string]interface{}{
			attribute_name: publishedDataResponse,
		},
	}, nil
}

func (b *backend) getAuthorityAttrs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority_name := data.Get("authority_name").(string)
	attributes, err := b.getEntries(ctx, []string{AuthoritiesPath, authority_name})
	path := AUTHORITY_PATH + "/" + authority_name

	if err != nil {
		return nil, fmt.Errorf("existence check failed: %s", err)
	}

	if len(attributes) == 0 {
		return logical.ErrorResponse("The Authority with name %s does not own any attributes", authority_name), nil
	}

	var publishedDataResponse []map[string]struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}
	for _, attribute := range attributes {
		alphai, yi, err := b.getKeyData(ctx, req, path, attribute, false)
		if err != nil {
			return nil, err
		}

		attributeToData := make(map[string]struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		})

		attributeToData[attribute] = struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		}{
			Alphai: alphai.String(),
			Yi:     yi.String(),
		}

		publishedDataResponse = append(publishedDataResponse, attributeToData)

	}

	return &logical.Response{
		Data: map[string]interface{}{
			authority_name: publishedDataResponse,
		},
	}, nil

}

func (b *backend) getDistinctCommonAttr(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	attribute_name := strings.ToUpper(data.Get("attribute_name").(string))
	path := COMMON_PATH

	alphai, yi, err := b.getKeyData(ctx, req, path, attribute_name, false)
	if err != nil {
		return nil, fmt.Errorf("existence check failed: %s", err)
	}

	if alphai == nil || yi == nil {
		return logical.ErrorResponse("A Common Attribute with the identifier %s does not exist", attribute_name), nil
	}

	var publishedDataResponse = struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}{
		Alphai: alphai.String(),
		Yi:     yi.String(),
	}

	return &logical.Response{
		Data: map[string]interface{}{
			attribute_name: publishedDataResponse,
		},
	}, nil

}

func (b *backend) getCommonAttrs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	attributes, err := b.getEntries(ctx, []string{COMMON_PATH})
	if err != nil {
		return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	var publishedDataResponse []map[string]struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}
	for _, attribute := range attributes {
		alphai, yi, err := b.getKeyData(ctx, req, COMMON_PATH, attribute, false)
		if err != nil {
			return nil, err
		}

		attributeToData := make(map[string]struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		})

		attributeToData[attribute] = struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		}{
			Alphai: alphai.String(),
			Yi:     yi.String(),
		}

		publishedDataResponse = append(publishedDataResponse, attributeToData)

	}

	return &logical.Response{
		Data: map[string]interface{}{
			"common_attributes": publishedDataResponse,
		},
	}, nil

}
