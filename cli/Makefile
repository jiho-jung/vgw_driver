BIN="vgw_cli"

all: clean
	go build -o vgw_cli

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

clean: 
	rm -f $(BIN)

run:
	sudo ./$(BIN) ct show

up:
	scp ./$(BIN) lb9:~/
