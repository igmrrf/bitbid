PYTHON ?= python3
SECRETS_CATALOG ?= secrets/prod.enc.yaml

.PHONY: secrets-catalog-init secrets-catalog-check secrets-report secrets-catalog-test

# SECRETS_RECIPIENT is an explicitly approved public age recipient, never an identity.
secrets-catalog-init:
	@$(PYTHON) scripts/secrets-catalog.py init --recipient "$(SECRETS_RECIPIENT)" --catalog "$(SECRETS_CATALOG)"

secrets-catalog-check:
	@$(PYTHON) scripts/secrets-catalog.py check --catalog "$(SECRETS_CATALOG)"

secrets-report:
	@$(PYTHON) scripts/secrets-catalog.py report --catalog "$(SECRETS_CATALOG)"

secrets-catalog-test:
	@$(PYTHON) scripts/test-secrets-catalog.py
