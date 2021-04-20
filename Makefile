PROGRAM_NAME=kalitorify
VERSION=1.26.1

DATA_DIR=/usr/share
DOCS_DIR=$(DATA_DIR)/doc
PROGRAM_DIR=/usr/local/bin


install:

	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(DATA_DIR)/$(PROGRAM_NAME)/data
	mkdir -p $(DATA_DIR)/$(PROGRAM_NAME)/backups
	install -Dm644 data/* $(DATA_DIR)/$(PROGRAM_NAME)/data

uninstall:

	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DATA_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
