package abe

import (
	"context"

	"github.com/Nik-U/pbc"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) abeGlobalSetup() (*pbc.Element, []byte) {
	params, _ := pbc.NewParamsFromString(`type a
	q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
	h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
	r 730750818665451621361119245571504901405976559617
	exp2 159
	exp1 107
	sign1 1
	sign0 1`)

	savedParams := []byte(params.String())
	pairing := params.NewPairing()
	globalECElement := pairing.NewG1().Rand()
	return globalECElement, savedParams
}

func (b *backend) initializeABE(ctx context.Context, req *logical.InitializationRequest) error {

	entry, err := b.storage.Get(ctx, coreABEGroupKeyPath)

	b.Logger().Info("Starting initialization for the ABE Plugin")

	if err != nil {
		b.Logger().Error("error running initialization", "error", err)
		return err
	}

	if entry == nil {

		ecElement, params := b.abeGlobalSetup()

		encoded := encodedG{
			EncodedG: ecElement.CompressedBytes(),
			Params:   params,
		}

		b.abeCache.SetDefault(abecache, ecElement)

		b.dataStore(ctx, encoded, coreABEGroupKeyPath)

		// Create a STATIC DOMAIN-WIDE System-Attribute named SA
		if b.sa_enabled {
			b.Logger().Info("System-Attribute is enabled. Creating a STATIC DOMAIN-WIDE System-Attribute named SA...")
			attributes := []string{"SA"}

			for _, attribute := range attributes {

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

				constructedPath := constructPath([]string{SYSTEM_ATTR_PATH})

				b.dataKeyStore(ctx, publicData, privateData, constructedPath, attribute)
			}
			b.Logger().Info("STATIC DOMAIN-WIDE System-Attribute named SA is created")
		} else {
			b.Logger().Info("System-Attribute is disabled. Will not create a STATIC DOMAIN-WIDE System-Attribute named SA")
		}


	} else {
		b.Logger().Info("Initialization error", "the plugin is already initialized!")
		ecElement, _ := b.loadEC(ctx)
		b.abeCache.SetDefault(abecache, ecElement)
	}

	return nil
}
