package abe

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	cache "github.com/patrickmn/go-cache"
)

var sa_enabled string

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(ctx, conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType returns the factory
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b, err := Backend(ctx, conf)
		if err != nil {
			return nil, err
		}
		b.BackendType = backendType
		if err = b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend returns a new Backend framework struct
func Backend(ctx context.Context, conf *logical.BackendConfig) (*backend, error) {
	var b backend

	sa_enabled, _ := strconv.ParseBool(sa_enabled)

	var backendPaths = framework.PathAppend(
			pathAuthoritySetup(&b),
			pathAttributes(&b),
			pathKeygenSetup(&b),
			pathEncrypt(&b),
			pathFullDecrypt(&b),
			pathBuilderPath(&b),
		)


	if sa_enabled {
		backendPaths = framework.PathAppend(
			pathSysDecrypt(&b),
			pathSysKeygenSetup(&b), 
			backendPaths,
		)
	}
	

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{},

			Root: []string{
				"config/*",
			},

			SealWrapStorage: []string{
				coreABEGroupKeyPath,
				SYSTEM_ATTR_PATH + "/",
				AUTHORITY_PATH + "/",
				COMMON_PATH + "/",
				SUBJECTS_PATH + "/",
			},
		},

		Paths: backendPaths,

		InitializeFunc: b.initializeABE,

		Secrets:     []*framework.Secret{},
	}

	b.abeCache = cache.New(0, 30*time.Second)

	b.crlLifetime = time.Hour * 72
	b.tidyCASGuard = new(uint32)
	b.storage = conf.StorageView
	
	b.sa_enabled = sa_enabled

	return &b, nil
}

type backend struct {
	*framework.Backend

	storage      logical.Storage
	abeCache     *cache.Cache
	crlLifetime  time.Duration
	tidyCASGuard *uint32
	sa_enabled   bool
}

const backendHelp = `
Hashicorp Vault Secrets Engine (plugin) with ABE (Attribute Based Encryption) capabilities
`
