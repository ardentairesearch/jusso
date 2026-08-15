# OpenAPI Source

This directory contains the maintainable split-source OpenAPI spec.

The generated single-file artifact remains at:

```bash
docs/agent-integration/openapi.yaml
```

Agent tooling, installers, ChatGPT custom actions, and code generators should
keep consuming that bundled file.

When editing the API spec:

1. Update the relevant file under `paths/` or `components/`.
2. Rebuild the bundled artifact:

   ```bash
   ruby docs/agent-integration/openapi/bundle.rb
   ```

3. Validate the generated file:

   ```bash
   ruby -e "require 'yaml'; YAML.load_file('docs/agent-integration/openapi.yaml')"
   ```

## Layout

- `root.yaml` contains top-level OpenAPI metadata and the bundle manifest.
- `paths/core.yaml` contains public, wallet, generic simulation/execution, and status endpoints.
- `paths/aave-v3.yaml` contains Aave V3 protocol endpoints.
- `paths/balancer-v3.yaml` contains Balancer V3 protocol endpoints.
- `paths/compound-v3.yaml` contains Compound III protocol endpoints.
- `paths/gmx-v2.yaml` contains GMX V2 protocol endpoints.
- `components/common.yaml` contains shared auth, responses, and generic schemas.
- `components/aave-v3.yaml` contains Aave protocol schemas.
- `components/balancer-v3.yaml` contains Balancer protocol schemas.
- `components/compound-v3.yaml` contains Compound protocol schemas.
- `components/gmx-v2.yaml` contains GMX protocol schemas.
