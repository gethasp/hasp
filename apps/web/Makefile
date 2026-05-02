.PHONY: bootstrap check deploy-downloads

bootstrap:
	@bash ../../scripts/bootstrap_web_tools.sh

check: bootstrap
	@pnpm check
	@HASP_RELEASE_METADATA_SHA256="$${HASP_RELEASE_METADATA_SHA256:-0000000000000000000000000000000000000000000000000000000000000000}" \
	  HASP_RELEASE_MIN_SEQUENCE="$${HASP_RELEASE_MIN_SEQUENCE:-0}" \
	  pnpm exec wrangler deploy --dry-run --config ./downloads/wrangler.toml >/dev/null

deploy-downloads:
	@pnpm exec wrangler deploy --config ./downloads/wrangler.toml
