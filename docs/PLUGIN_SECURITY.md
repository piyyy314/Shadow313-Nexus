# Shadow313 plugin security model

## Trust policy

External plugins are signature-required by default. The runtime reads
`plugins.require_signed`, which can be overridden with
`SHADOW313_REQUIRE_SIGNED=false` for a controlled development environment.
Do not disable this policy for production deployments.

Sign a plugin directory before installation:

```bash
shadow313 plugin --sign ./my-plugin
shadow313 plugin --verify ./my-plugin
shadow313 plugin --install ./my-plugin
shadow313 plugin --verify-all
```

The signature covers every regular file path and file-content hash in the
plugin directory. Changing a source file, manifest, or other artifact after
signing invalidates the signature. The detached signature is stored as
`plugin.shadow313sig`.

## Key management

On first signing, Shadow313 generates a 256-bit local HMAC key at
`~/.shadow313/plugin-artifact-signing.key` with owner-only file permissions.
Back up and protect this key. A plugin signed with a different key cannot be
verified by this installation.

For multiple hosts, configure the same high-entropy secret through
`SHADOW313_PLUGIN_SIGNING_KEY` using an approved secret manager. The value
must be at least 32 bytes. Do not commit it to the repository or place it in
a public `.env` file.

This local HMAC mechanism provides integrity and local trust enforcement; it
does not provide public-key provenance or non-repudiation. Organizations that
need publisher identity and portable trust should use a managed Sigstore or
organizational signing service in a future adapter.

## Execution boundary

Plugin code is executed only on Linux when Bubblewrap (`bwrap`) is installed
and usable. The runner creates isolated namespaces including a network
namespace, mounts the plugin and runtime read-only, provides a private tmpfs,
uses a minimal environment, and applies CPU, address-space, file-size, and
file-descriptor limits. If the sandbox is unavailable, the plugin is not run.

Plugin-declared dependencies are never installed into the host Python
environment. They must be built into a dedicated, isolated plugin image.

## Operational status

A valid signature proves that the artifact matches the trusted local signing
key. It does not prove that the plugin is benign. Review plugin source,
dependencies, and permissions before signing it. Sandbox status and plugin
execution results must be treated separately from signature verification.
