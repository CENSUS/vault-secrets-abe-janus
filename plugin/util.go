package abe

const (
	//coreABEGroupKeyPath is where the BASE EC element is stored
	coreABEGroupKeyPath		= "config/ecelement"

	AuthoritiesPath			= "authority_keys"
	abecache				= "ecData"

	SYSTEM_ATTR_PATH		= "SYSTEM_ATTRIBUTES"
	AUTHORITY_PATH			= "AUTHORITY_ATTRIBUTES"
	COMMON_PATH				= "COMMON_ATTRIBUTES"

	SUBJECTS_PATH			= "SUBJECTS"
	GIDS_PATH				= "/GIDS/"

	PRIVATE_ACCESSOR		= "PRIVATE_KEY_DATA"
	PUBLIC_ACCESSOR			= "PUBLIC_KEY_DATA"

	KEYGEN_ENDPOINT			= "keygen"
	SYSTEM_KEYGEN_ENDPOINT	= "syskeygen"
	ENCRYPT_ENDPOINT		= "encrypt"
	SYS_DECRYPT_ENDPOINT	= "sysdecrypt"
	FULL_DECRYPT_ENDPOINT	= "decrypt"
	ADD_ATTRIBUTES_ENDPOINT	= "addattributes"

)

type encodedG struct {
	EncodedG []byte
	Params   []byte
}

type mergedAttributes struct {
	attribute string
	isCommon  bool
}

type majorityConcernsInfo struct {
	Attribute map[string]map[string][]string
}

type keysData struct {
	Attribute string `json:"Attribute"`
	Alphai    []byte `json:"alphai"`
	Yi        []byte `json:"yi"`
}

type keysDataAsResponse struct {
	Attribute string `json:"Attribute"`
	Alphai    string `json:"alphai"`
	Yi        string `json:"yi"`
}

type gidData struct {
	GID                  string                       `json:"GID"`
	COMMON_ATTRIBUTES    map[string][]byte            `json:"COMMON_ATTRIBUTES"`
	AUTHORITY_ATTRIBUTES map[string]map[string][]byte `json:"AUTHORITY_ATTRIBUTES"`
	SYSTEM_ATTRIBUTES    []string `json:"SYSTEM_ATTRIBUTES"`
}

type cryptogram struct {
	C0               []byte            `json:"C0"`
	C1               map[string][]byte `json:"C1"`
	C2               map[string][]byte `json:"C2"`
	C3               map[string][]byte `json:"C3"`
	SysDecrypted     []byte            `json:"SysDecrypted,omitempty"`
	EncryptedMessage []byte            `json:"EncryptedMessage"`
	CipherIV         []byte            `json:"CipherIV"`
	PolicyStr        string            `json:"Policy"`
}
