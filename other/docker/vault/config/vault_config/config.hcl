default_lease_ttl = "24h"
disable_mlock = "true"
max_lease_ttl = "8760h"

backend "file" {
    path = "/home/vault/config/data"
}

api_addr = "https://127.0.0.1:8200"
ui = "true"

listener "tcp" {
    tls_disable = "false"
    address = "[::]:8200"
    tls_client_ca_file = "/home/vault/config/certificates/ca/ca.crt"
    tls_cert_file = "/home/vault/config/certificates/tls/tls.crt"
    tls_key_file = "/home/vault/config/certificates/tls/tls.key"
}

plugin_directory = "/vault/plugins"