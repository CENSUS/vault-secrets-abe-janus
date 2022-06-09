package abe

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathBuilder(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entries, err := req.Storage.List(ctx, "")

	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func pathBuilderPath(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("abeEndPoints"),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathBuilder,
			},
		},
	}
}
