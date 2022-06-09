package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAuthoritySetup(b *backend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: GetPath(framework.GenericNameRegex("authorityName") + "/" + strings.ToLower(ADD_ATTRIBUTES_ENDPOINT)),

			Fields: map[string]*framework.FieldSchema{
				"authorityAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "[Required] An array with the names of the Authority Attributes (e.g. `authorityAttributes: [`a_attr1`,...`a_attrN`]`).",
					Required:    true,
				},
				"commonAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "[Required] An array with the names of the Common Attributes (e.g. `commonAttributes: [`c_attr1`,...`c_attrN`]`).",
					Required:    true,
				},
				"authorityName": {
					Type:        framework.TypeString,
					Description: "[Required] The authority's name that adds the new Attributes.",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.AuthoritySetup,
				logical.CreateOperation: b.AuthoritySetup,
			},
		},
		{
			Pattern: GetPath(AuthoritiesPath + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: GetPath(AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITY_OR_ATTRIBUTE") + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: GetPath(AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITY_OR_ATTRIBUTE") + "/" + framework.GenericNameRegex("ATTRIBUTE") + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: GetPath(AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITY_OR_ATTRIBUTE") + "/" + framework.GenericNameRegex("ATTRIBUTE") + "/" + framework.GenericNameRegex("DATA_ACCESS") + "/?$"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleRead,
			},
		},
	}
}

func (b *backend) AuthoritySetup(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority := data.Get("authorityName").(string)
	authorityAttrs := data.Get("authorityAttributes").([]string)
	commonAttrs := data.Get("commonAttributes").([]string)

	if len(authorityAttrs) == 0 && len(commonAttrs) == 0 {
		return logical.ErrorResponse("Wrong number of initialization attributes. Please, provide some Authority/Common attributes"), nil
	}

	// Turn every Attribute to uppercase in order to avoid conflicts in the future
	authorityAttrs = stringsToUpper(authorityAttrs)
	commonAttrs = stringsToUpper(commonAttrs)

	// Checks for Reserved Attributes [SYSTEM, COMMON, AUTHORITY]
	reservedAttrsList, hasReservedAttrs, err := b.attributesNotReserved(ctx, authorityAttrs, commonAttrs)
	if err != nil {
		return nil, err
	}
	if hasReservedAttrs {
		return logical.ErrorResponse(fmt.Sprintf("These Attributes are already reserved and can not be reused: %s", reservedAttrsList)), nil
	}
		
	

	mergedAttrs := make([]*mergedAttributes, 0)
	var existanceMessage string

	if len(commonAttrs) > 0 {
		attrsAlreadyExist, message, err := b.mergeAttributes(ctx, &mergedAttrs, commonAttrs, "", true, true)
		if err != nil {
			return nil, fmt.Errorf("existence check failed: %s", err)
		}
		if attrsAlreadyExist {
			existanceMessage += ("Common Attributes: " + message)
		}
	}
	if len(authorityAttrs) > 0 {
		attrsAlreadyExist, message, err := b.mergeAttributes(ctx, &mergedAttrs, authorityAttrs, authority, false, true)
		if err != nil {
			return nil, fmt.Errorf("existence check failed: %s", err)
		}
		if attrsAlreadyExist {
			if existanceMessage != "" {
				existanceMessage += " - "
			}
			existanceMessage += ("Authority Attributes: " + message)
		}
	}
	if existanceMessage != "" {
		existanceMessage = fmt.Sprintf("Attribute(s) already exist: " + existanceMessage)
		return logical.ErrorResponse(existanceMessage), nil
	}

	var publicDataResponseCommon []*keysDataAsResponse
	var publicDataResponseAuthority []*keysDataAsResponse

	ecElement := b.getABEElement()

	for _, value := range mergedAttrs {
		attribute := strings.ToUpper(value.attribute)
		alpha_i, y_i := ecElement.Pairing().NewZr(), ecElement.Pairing().NewZr()
		alpha_i.Rand()
		y_i.Rand()

		e_gg_alpha_i := ecElement.Pairing().NewGT().Pair(ecElement, ecElement).ThenPowZn(alpha_i)
		g_y_i := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(y_i)

		publicData := &keysData{
			Attribute: attribute,
			Alphai:    e_gg_alpha_i.Bytes(),
			Yi:        g_y_i.Bytes(),
		}

		privateData := &keysData{
			Attribute: attribute,
			Alphai:    alpha_i.Bytes(),
			Yi:        y_i.Bytes(),
		}

		var constructedPath string

		if value.isCommon {
			constructedPath = constructPath([]string{COMMON_PATH})
		} else {
			constructedPath = constructPath([]string{AUTHORITY_PATH, authority})
		}

		if err := b.dataKeyStore(ctx, publicData, privateData, constructedPath, attribute); err != nil {
			return nil, fmt.Errorf("failed to save the new attributes: %s", err)
		}

		publicDataResponseConstructor := &keysDataAsResponse{
			Attribute: attribute,
			Alphai:    e_gg_alpha_i.String(),
			Yi:        g_y_i.String(),
		}

		if value.isCommon {
			publicDataResponseCommon = append(publicDataResponseCommon, publicDataResponseConstructor)
		} else {
			publicDataResponseAuthority = append(publicDataResponseAuthority, publicDataResponseConstructor)
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"generated_data": map[string]interface{}{
				"public_segments": map[string]interface{}{
					"common_attributes":    publicDataResponseCommon,
					"authority_attributes": publicDataResponseAuthority,
				},
			},
		},
	}, nil
}