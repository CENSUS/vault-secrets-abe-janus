package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSysKeygenSetup(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.ToLower(SYSTEM_KEYGEN_ENDPOINT) + "/" + framework.GenericNameRegex("system_attribute") + "/" + framework.GenericNameRegex("authority"),

			Fields: map[string]*framework.FieldSchema{
				"authority": {
					Type:        framework.TypeString,
					Description: "[Required] The Authority that asks for a System Attribute.",
					Required:    true,
				},
				"system_attribute": {
					Type:        framework.TypeString,
					Description: "[Required] The name of the System Attribute.",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.systemAttributesKeygen,
				logical.CreateOperation: b.systemAttributesKeygen,
			},
		},
	}
}

func (b *backend) systemAttributesKeygen(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority := data.Get("authority").(string)
	system_attribute := strings.ToUpper(data.Get("system_attribute").(string))

	ecElement := b.getABEElement()

	gidMapper := b.createHashMapper(ecElement)

	alphai, yi, err := b.getKeyData(ctx, req, SYSTEM_ATTR_PATH, system_attribute, true)
	if err != nil {
		return nil, fmt.Errorf("failed: %s", err)
	}

	gidData, err := b.loadGIDData(ctx, req, authority)
	if err != nil {
		return nil, fmt.Errorf("error with GID data: %s", err)
	}


	hashedGIDInEC := gidMapper(authority)
	fieldBase := ecElement.Pairing().NewG1()
	fieldh := ecElement.Pairing().NewG1().Set(hashedGIDInEC).ThenPowZn(yi)
	fieldR := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(alphai)

	fieldBase.Set(fieldR).ThenMul(fieldh)

	if gidData.GID == "" {
		gidData.GID = authority
	}

	gidData.SYSTEM_ATTRIBUTES = append(gidData.SYSTEM_ATTRIBUTES, system_attribute)
	b.dataStore(ctx, gidData, SUBJECTS_PATH)

	return &logical.Response{
		Data: map[string]interface{}{
			"System Attribute": system_attribute,
			"Authority:":     authority,
		},
	}, nil
}
