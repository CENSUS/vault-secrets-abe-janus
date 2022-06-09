package abe

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Nik-U/pbc"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) getABEElement() *pbc.Element {

	element, exists := b.abeCache.Get(abecache)

	if !exists {
		b.abeCache.SetDefault(abecache, nil)
	}

	ecElement := element.(*pbc.Element)

	return ecElement
}

func (b *backend) createHashMapper(ecElement *pbc.Element) func(GID string) *pbc.Element {
	hash := sha256.New()

	mapper := func(GID string) *pbc.Element {
		hash.Reset()
		hash.Write([]byte(GID))

		mapGID := ecElement.Pairing().NewG1()
		mapGID.SetFromHash(hash.Sum([]byte(GID)))

		return mapGID
	}

	return mapper
}

func (b *backend) loadEC(ctx context.Context) (*pbc.Element, error) {

	out, err := b.storage.Get(ctx, coreABEGroupKeyPath)

	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	if out == nil {
		return nil, nil
	}

	var ecData encodedG
	if err := jsonutil.DecodeJSON(out.Value, &ecData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %s", err)
	}

	ecParams := string([]byte(ecData.Params))

	loadedParams, _ := pbc.NewParamsFromString(ecParams)

	pairing := loadedParams.NewPairing()

	element := pairing.NewG1().SetCompressedBytes(ecData.EncodedG)

	return element, nil
}

func (b *backend) mergeAttributes(ctx context.Context, mergedAttrs *[]*mergedAttributes, providedAttributes []string, authority string, isCommonAttrs bool, isNewAddition bool) (bool, string, error) {
	var storedAttributes []string
	var err error
	if isCommonAttrs {
		storedAttributes, err = b.getEntries(ctx, []string{COMMON_PATH})
		if err != nil {
			return false, "", err
		}
	} else {
		storedAttributes, err = b.getEntries(ctx, []string{AUTHORITY_PATH, authority})
		if err != nil {
			return false, "", err
		}
	}
	if isNewAddition {
		attributeCheck, attrAlreadyExist := b.checkAttrExistence(storedAttributes, providedAttributes)
		message := fmt.Sprintf("%s", attributeCheck)
		if attrAlreadyExist {
			return attrAlreadyExist, message, nil
		}
	} else {
		attributeCheck, attrDontExist := b.checkNonExistentAttr(storedAttributes, providedAttributes)
		if attrDontExist {
			message := fmt.Sprintf("%s", attributeCheck)
			return attrDontExist, message, nil
		}
	}

	for _, attribute := range providedAttributes {
		var newAttribute mergedAttributes
		newAttribute.attribute = attribute
		newAttribute.isCommon = isCommonAttrs
		*mergedAttrs = append(*mergedAttrs, &newAttribute)
	}
	return false, "", nil
}

func (b *backend) checkAttrExistence(aggregratedValues []string, values []string) ([]string, bool) {
	var items []string
	for _, itemValueAggregated := range aggregratedValues {
		for _, itemValue := range values {
			if strings.EqualFold(strings.ToUpper(itemValueAggregated), strings.ToUpper(itemValue)) {
				items = append(items, itemValue)
				break
			}
		}
	}
	if len(items) > 0 {
		return items, true
	} else {
		return nil, false
	}
}

func (b *backend) checkNonExistentAttr(aggregratedValues []string, valuesToCheck []string) ([]string, bool) {
	var items []string
	if aggregratedValues == nil {
		return valuesToCheck, true
	}
	for _, itemValue := range valuesToCheck {
		for i, itemValueAggregated := range aggregratedValues {
			if strings.EqualFold(strings.ToUpper(itemValue), strings.ToUpper(itemValueAggregated)) {
				break
			}
			if i == len(aggregratedValues)-1 {
				items = append(items, itemValue)
			}
		}
	}

	if len(items) > 0 {
		return items, true
	} else {
		return nil, false
	}
}

func (b *backend) getEntries(ctx context.Context, pathAr []string) ([]string, error) {
	path := ""

	for pos, pathObject := range pathAr {
		path += pathObject
		if pos < len(pathAr)-1 {
			path += "/"
		}
	}

	entries, err := b.storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	var modifiedEntries []string

	for _, entry := range entries {
		entry = strings.TrimSuffix(entry, "/")
		entry = strings.TrimPrefix(entry, "/")

		modifiedEntries = append(modifiedEntries, entry)
	}

	return modifiedEntries, nil
}

func (b *backend) dataKeyStore(ctx context.Context, publicData interface{}, privateData interface{}, path string, endpoint string) error {

	var storageLocationPublished string
	var storageLocationPrivate string

	if !strings.HasSuffix(path, "/") {
		endpoint = "/" + endpoint
	}
	if !strings.HasPrefix(PRIVATE_ACCESSOR, "/") {
		endpoint =  endpoint + "/" 
	}

	buffer_published, err := json.Marshal(publicData)
	if err != nil {
		return err
	}

	buffer_private, err := json.Marshal(privateData)
	if err != nil {
		return err
	}

	storageLocationPublished = path + endpoint + PUBLIC_ACCESSOR
	storageLocationPrivate = path + endpoint + PRIVATE_ACCESSOR

	publicEntry := &logical.StorageEntry{
		Key:   storageLocationPublished,
		Value: buffer_published,
	}

	privateEntry := &logical.StorageEntry{
		Key:   storageLocationPrivate,
		Value: buffer_private,
	}

	if err := b.storage.Put(ctx, publicEntry); err != nil {
		return err
	}
	if err := b.storage.Put(ctx, privateEntry); err != nil {
		b.storage.Delete(ctx, storageLocationPublished)
		return err
	}

	return nil
}

func (b *backend) dataStore(ctx context.Context, data interface{}, pathOptions ...string) error {

	// pathOptions must always be like:
	// pathOptions[0] must be the prePathType
	// pathOptions[1]...[n-1] can be any other option we may need
	// E.g. pathOptions[1] could be "endpoint"

	if pathOptions[0] == "" {
		return errors.New("error in path options")
	}

	var prePathType = pathOptions[0]

	var storageLocation = ""

	buf, err := json.Marshal(data)

	if err != nil {
		return fmt.Errorf("json encoding failed: %s", err)
	}

	if prePathType == coreABEGroupKeyPath {
		storageLocation = coreABEGroupKeyPath
		goto DONE_CHECKING
	}

	if prePathType == SUBJECTS_PATH {
		GID := data.(gidData).GID
		storageLocation = prePathType + GIDS_PATH + GID

	} else {
		storageLocation = prePathType + pathOptions[1] + pathOptions[2]
	}

DONE_CHECKING:
	entry := &logical.StorageEntry{
		Key:   storageLocation,
		Value: buf,
	}

	if err := b.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %s", err)
	}

	return nil
}

func (b *backend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	keys, err := req.Storage.List(ctx, req.Path)

	if err != nil {
		return nil, err
	}

	strippedKeys := make([]string, len(keys))
	for i, key := range keys {
		strippedKeys[i] = strings.ToUpper(strings.TrimPrefix(key, req.Path))
	}

	// Generate the response
	return logical.ListResponse(strippedKeys), nil
}

func (b *backend) checkAttributesAvailability(attributes map[string]*pbc.Element, attributesList map[string]keysData) (bool, map[string]struct {Available bool "json:\"Available\""}) {
	unavailableAttrExists := false

	notAvailableAttributesResponse := make(map[string]struct {
		Available bool "json:\"Available\""
	})

	for attr := range attributes {
		attribute := strings.ToUpper(attr)

		if attributesList[attribute].Alphai == nil || attributesList[attribute].Yi == nil {
			unavailableAttrExists = true
			notAvailableAttributesResponse[attribute] = struct {
				Available bool "json:\"Available\""
			}{
				Available: false,
			}
		} else {
			notAvailableAttributesResponse[attribute] = struct {
				Available bool "json:\"Available\""
			}{
				Available: true,
			}
		}
	}

	return unavailableAttrExists, notAvailableAttributesResponse
}

func (b *backend) attributesNotReserved(ctx context.Context, authorityAttributes []string, commonAttributes []string) ([]string, bool, error) {
	reservedEntries, err := b.allAvailableAttributes(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("read failed: %s", err)
	}

	var items []string

	for _, reservedAttr := range reservedEntries {
		if len(authorityAttributes) > 0 {
			for _, value := range authorityAttributes {
				if reservedAttr == value {
					items = append(items, value)
					continue
				}
			}
		}

		if len(commonAttributes) > 0 {
			for _, value := range commonAttributes {
				if reservedAttr == value {
					items = append(items, value)
					continue
				}
			}
		}
	}

	if len(items) > 0 {
		return items, true, nil
	} else {
		return nil, false, nil
	}
}

func (b *backend) allAvailableAttributes(ctx context.Context) ([]string, error) {
	// Common Attributes Entries
	entries, err := b.getEntries(ctx, []string{COMMON_PATH})
	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	// Authority Attributes Entries
	authEntries, err := b.getEntries(ctx, []string{AUTHORITY_PATH})
	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	for _, authority := range authEntries {
		attributeEntries, err := b.getEntries(ctx, []string{AUTHORITY_PATH, authority})
		if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
		}
		entries = append(entries, attributeEntries...)
	}

	if b.sa_enabled {
		// System Attributes Entries
		systemEntries, err := b.getEntries(ctx, []string{SYSTEM_ATTR_PATH})
		if err != nil {
			return nil, fmt.Errorf("read failed: %s", err)
		}
		entries = append(entries, systemEntries...)
	}


	return entries, nil

}

func (b *backend) allAttributesPutTogether(ctx context.Context, req *logical.Request) (map[string]keysData, error) {
	commonEntries, err := b.getCommonAttributes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("internal error - failed to read Common Attributes: %s", err)
	}

	authoritiesEntries, err := b.getAuthoritiesAttributes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("internal error - failed to read Authorities' Attributes: %s", err)
	}

	systemAttributesEntries, err := b.getSystemAttributes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("internal error - failed to read System Attributes: %s", err)
	}

	mergedAttributes := make(map[string]keysData)
	for k, v := range commonEntries {
		mergedAttributes[k] = v
	}
	for k, v := range authoritiesEntries {
		_, _k, err := b.separateAuthorityFromAttribute(k)
		if err != nil {
			return nil, fmt.Errorf("internal error - failed to read Authority Attributes: %s", err)
		}
		mergedAttributes[_k] = v
	}
	for k, v := range systemAttributesEntries {
		mergedAttributes[k] = v
	}

	return mergedAttributes, nil
}

func (b *backend) getSystemAttributes(ctx context.Context, req *logical.Request) (map[string]keysData, error) {
	entries, err := b.getEntries(ctx, []string{SYSTEM_ATTR_PATH})
	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	data := make(map[string]keysData)

	for _, systemAttrEntry := range entries {
			attributeEntryAsDir := "/" + systemAttrEntry + "/"

			var newData keysData

			out, err := req.Storage.Get(ctx, SYSTEM_ATTR_PATH+attributeEntryAsDir+PUBLIC_ACCESSOR)

			if err != nil || out == nil {
				return nil, fmt.Errorf("internal error - could not load the appropriate attributes: %s", err)
			}

			if err := jsonutil.DecodeJSON(out.Value, &newData); err != nil {
				return nil, fmt.Errorf("internal error - json decoding failed: %s", err)
			}

			data[systemAttrEntry] = newData 
	}

	return data, nil
}

func (b *backend) getAuthoritiesAttributes(ctx context.Context, req *logical.Request) (map[string]keysData, error) {
	entries, err := b.getEntries(ctx, []string{AUTHORITY_PATH})

	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	data := make(map[string]keysData)

	for _, authority := range entries {
		attributeEntries, err := b.getEntries(ctx, []string{AUTHORITY_PATH, authority})

		if err != nil {
			return nil, fmt.Errorf("read failed: %s", err)
		}

		for _, attributeEntry := range attributeEntries {
			entryAsDir := "/" + authority + "/"
			attributeEntryAsDir := attributeEntry + "/"

			var newData keysData

			out, err := req.Storage.Get(ctx, AUTHORITY_PATH+entryAsDir+attributeEntryAsDir+PUBLIC_ACCESSOR)

			if err != nil || out == nil {
				return nil, fmt.Errorf("internal error - could not load the appropriate authority attributes: %s", err)
			}

			if err := jsonutil.DecodeJSON(out.Value, &newData); err != nil {
				return nil, fmt.Errorf("internal error - json decoding failed: %s", err)
			}

			attributeEntry = attributeEntry + "[" + strings.ToUpper(authority) + "]"
			
			data[attributeEntry] = newData 
		}
	}

	return data, nil
}

func (b *backend) getCommonAttributes(ctx context.Context, req *logical.Request) (map[string]keysData, error) {
	entries, err := b.getEntries(ctx, []string{COMMON_PATH})
	if err != nil {
		return nil, fmt.Errorf("read failed: %s", err)
	}

	data := make(map[string]keysData)

	for _, commonAttrEntry := range entries {
			attributeEntryAsDir := "/" + commonAttrEntry + "/"

			var newData keysData

			out, err := req.Storage.Get(ctx, COMMON_PATH+attributeEntryAsDir+PUBLIC_ACCESSOR)

			if err != nil || out == nil {
				return nil, fmt.Errorf("internal error - could not load the appropriate attributes: %s", err)
			}

			if err := jsonutil.DecodeJSON(out.Value, &newData); err != nil {
				return nil, fmt.Errorf("internal error - json decoding failed: %s", err)
			}

			data[commonAttrEntry] = newData 
	}

	return data, nil
}

func (b *backend) loadGIDData(ctx context.Context, req *logical.Request, endpoint string) (gidData, error) {

	var data gidData

	// Read the path
	out, err := req.Storage.Get(ctx, SUBJECTS_PATH+GIDS_PATH+endpoint)

	if err != nil {
		return data, fmt.Errorf("read failed: %s", err)
	}

	// Fast-path the no data case
	if out == nil {
		return data, nil
	}

	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return data, fmt.Errorf("json decoding failed: %s", err)
	}

	return data, nil
}

func (b *backend) getKeyData(ctx context.Context, req *logical.Request, path string, attribute string, needPrivateKeys bool) (*pbc.Element, *pbc.Element, error) {

	var ecElement = b.getABEElement()
	var endpoint = attribute
	var accessor string
	var dataLocation string

	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint = endpoint + "/"
	}
	
	if needPrivateKeys {
		accessor = PRIVATE_ACCESSOR
	} else {
		accessor = PUBLIC_ACCESSOR
	}
	
	if path != "" {
		dataLocation = path + endpoint + accessor
	} else {
		return nil, nil, nil //Should return an error
	}

	out, err := b.storage.Get(ctx, dataLocation)

	if err != nil {
		return nil, nil, fmt.Errorf("read failed: %s", err)
	}

	if out == nil {
		return nil, nil, nil
	}

	// Decode the data
	var data keysData
	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return nil, nil, fmt.Errorf("json decoding failed: %s", err)
	}

	alphai := ecElement.Pairing().NewZr().SetBytes(data.Alphai)
	yi := ecElement.Pairing().NewZr().SetBytes(data.Yi)

	return alphai, yi, nil
}

func (b *backend) separateAuthorityFromAttribute(authorityAttribute string) (string, string, error) {
	delimiter := "["

	attribute := strings.Split(authorityAttribute, delimiter)[0]
	authority := strings.Split(authorityAttribute, attribute)[1]

	regex, err := regexp.Compile(`[^\w]`)

	if err != nil {
		return "", "", fmt.Errorf("internal error %s", err)
	}

	authority = regex.ReplaceAllString(authority, "")

	return strings.ToUpper(authority), strings.ToUpper(attribute), nil

}