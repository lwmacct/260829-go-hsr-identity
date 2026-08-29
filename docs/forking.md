# Forking identity layers

The default module is intentionally a vertical package that can be taken over by a host application.

## Handler-only fork

Copy `internal/identity/handler` into the host. Keep the public service and repository behavior, but change routes, DTOs, cookies, middleware, or response envelopes.

## Full fork

Copy these directories together:

```text
pkg/identity/domain
internal/identity/handler
internal/identity/service
internal/identity/repository
```

Then replace imports, adjust the module composition root, add host-specific fields or policies, and remove the dependency on the upstream identity module. This is a deliberate source-ownership boundary; no historical compatibility API is required.
