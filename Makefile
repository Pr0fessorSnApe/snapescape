.PHONY: all build rust go api dashboard docker test clean

all: build

rust:
	cd engines/rust && cargo build --release

go:
	cd services/go-worker && go build -o ../../bin/snapescape-worker ./cmd/worker

api:
	cd services/python-api && pip install -r requirements.txt

dashboard:
	cd dashboard && npm install && npm run build

build: rust go dashboard

docker:
	docker compose up --build -d

test:
	cd engines/rust && cargo test
	cd services/python-api && python -m pytest tests/ -v

dev-api:
	cd services/python-api && python -m snapescape_api.main

dev-dashboard:
	cd dashboard && npm run dev

clean:
	cd engines/rust && cargo clean
	rm -rf bin/ dashboard/dist dashboard/node_modules

scan:
	./engines/rust/target/release/snapescape scan -d $(DOMAIN)
