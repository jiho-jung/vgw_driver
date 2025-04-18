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

reset:
	#sudo ./vgw_cli ct reset -z 100 --smac 52:54:88:88:89:6d --dmac 52:54:88:88:89:0b --sport 58948
	sudo ./vgw_cli ct reset -z 100 --sport 58948
