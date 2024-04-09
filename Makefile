.PHONY: all load clean

all: clean load run

run:
	sudo -s ~/p4app/docker/scripts/run.sh

load:
	sudo mkdir -p /p4app/ /tmp/p4app-logs/
	sudo cp ./* /p4app/

clean:
	sudo rm -rf /p4app/
	sudo rm -rf /tmp/p4app-logs/