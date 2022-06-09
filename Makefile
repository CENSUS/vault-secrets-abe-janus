build: 
	docker build -t vault-abe .

build-sa-enabled:
	docker build --build-arg sa_enabled=true -t vault-abe .

run:
	docker-compose -f other/docker/docker-compose.yml up --build --remove-orphans

every: clean-build build run

every-sa-enabled: clean-build build-sa-enabled run

clean-build: 
	sudo rm -rf ./other/docker/vault/config/data ./other/docker/vault/config/certificates ./other/docker/vault/config/vault_operator_secrets.json


