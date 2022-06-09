package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathKeygenSetup(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: GetPath(strings.ToLower(KEYGEN_ENDPOINT) + "/" + framework.GenericNameRegex("fromAuthority") + "/" + framework.GenericNameRegex("toGID")),

			Fields: map[string]*framework.FieldSchema{
				"authorityAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "The Authority Attributes to produce keys for.",
					Required:    true,
				},
				"commonAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "The common attributes to produce keys for.",
					Required:    true,
				},
				"fromAuthority": {
					Type:        framework.TypeString,
					Description: "The authority that is used.",
					Required:    true,
				},
				"toGID": {
					Type:        framework.TypeString,
					Description: "The GID to produce keys for.",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.keygen,
				logical.CreateOperation: b.keygen,
			},
		},
		{
			Pattern: GetPath(SUBJECTS_PATH + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: GetPath(SUBJECTS_PATH + GIDS_PATH + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: GetPath(SUBJECTS_PATH + GIDS_PATH + framework.GenericNameRegex("USER")),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type: framework.TypeString,
					Description: `The Path of a Client's Keys.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleRead,
				logical.ListOperation: b.handleList,
			},
		},
	}
}

func (b *backend) keygen(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	authorityAttrs := data.Get("authorityAttributes").([]string)
	commonAttrs := data.Get("commonAttributes").([]string)
	GID := data.Get("toGID").(string)
	authority := data.Get("fromAuthority").(string)

	if len(authorityAttrs) == 0 && len(commonAttrs) == 0 {
		return logical.ErrorResponse("Wrong number of attributes. Please, provide some Authority/Common attributes"), nil
	}

	// Turn every Attribute to uppercase in order to avoid conflicts
	authorityAttrs = stringsToUpper(authorityAttrs)
	commonAttrs = stringsToUpper(commonAttrs)

	gidData, err := b.loadGIDData(ctx, req, GID)
	if err != nil {
		return nil, fmt.Errorf("error with GID data: %s", err)
	}

	if gidData.GID == "" {
		gidData.GID = GID
	}

	mergedAttrs := make([]*mergedAttributes, 0)
	var existenceMessage string
	if len(commonAttrs) > 0 {
		attrsDontExist, message, err := b.mergeAttributes(ctx, &mergedAttrs, commonAttrs, "", true, false)
		if err != nil {
			return nil, fmt.Errorf("existence check failed: %s", err)
		}
		if attrsDontExist {
			existenceMessage += ("Common Attributes: " + message)
		}
	}
	if len(authorityAttrs) > 0 {
		attrsDontExist, message, err := b.mergeAttributes(ctx, &mergedAttrs, authorityAttrs, authority, false, false)
		if err != nil {
			return nil, fmt.Errorf("existence check failed: %s", err)
		}
		if attrsDontExist {
			if existenceMessage != "" {
				existenceMessage += " - "
			}
			existenceMessage += ("Authority Attributes: " + message)
		}
	}
	if existenceMessage != "" {
		existenceMessage = fmt.Sprintf("Non-existent attributes: " + existenceMessage)
		return logical.ErrorResponse(existenceMessage), nil
	}

	ecElement := b.getABEElement()
	
	gidMapper := b.createHashMapper(ecElement)
	hashedGIDInEC := gidMapper(GID)

	for _, mergedAttribute := range mergedAttrs {
		attribute := mergedAttribute.attribute
		isCommonAttribute := mergedAttribute.isCommon
		path := ""
		if isCommonAttribute {
			path = COMMON_PATH
		} else {
			path = AUTHORITY_PATH + "/" + authority
		}

		alphai, yi, err := b.getKeyData(ctx, req, path, attribute, true)
		if err != nil {
			return nil, fmt.Errorf("failed to load the necessary keys: %s", err)
		}

		fieldBase := ecElement.Pairing().NewG1()
		fieldh := ecElement.Pairing().NewG1().Set(hashedGIDInEC).ThenPowZn(yi)
		fieldR := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(alphai)

		fieldBase.Set(fieldR).ThenMul(fieldh)

		if isCommonAttribute {
			if gidData.COMMON_ATTRIBUTES == nil {
				gidData.COMMON_ATTRIBUTES = make(map[string][]byte)
			}
			gidData.COMMON_ATTRIBUTES[attribute] = fieldBase.Bytes()
		} else {
			if gidData.AUTHORITY_ATTRIBUTES == nil {
				gidData.AUTHORITY_ATTRIBUTES = make(map[string]map[string][]byte)
			}

			if gidData.AUTHORITY_ATTRIBUTES[authority] == nil {
				gidData.AUTHORITY_ATTRIBUTES[authority] = map[string][]byte{}
			}

			gidData.AUTHORITY_ATTRIBUTES[authority][attribute] = fieldBase.Bytes()
		}
	}

	b.dataStore(ctx, gidData, SUBJECTS_PATH)

	return &logical.Response{
		Data: map[string]interface{}{
			"Generated for (GID)":       GID,
			"Authority Keys generated:": authorityAttrs,
			"Common Keys generated:":    commonAttrs,
		},
	}, nil
}