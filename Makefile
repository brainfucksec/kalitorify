PROGRAM_NAME=kalitorify
VERSION=1.14.0

DATA_DIR=/usr/share
DOCS_DIR=$(DATA_DIR)/doc
PROGRAM_DIR=/usr/local/bin
BACKUP_DIR=/opt

install:
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(DATA_DIR)/$(PROGRAM_NAME)/data
	install -Dm644 data/* $(DATA_DIR)/$(PROGRAM_NAME)/data
	mkdir -p $(BACKUP_DIR)/$(PROGRAM_NAME)/backups

uninstall:
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DATA_DIR)/$(PROGRAM_NAME)
	rm -Rf $(BACKUP_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
