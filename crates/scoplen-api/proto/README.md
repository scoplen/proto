# Internal protobuf contracts

The `spl.gateway.v1.Control` and `spl.agent.v1.Agent` definitions are authored
from `scoplen-docs/09-gateway-and-host-agent.md`. They are source contracts for
the internal mTLS gRPC channels; no client or server repository may invent a
parallel message shape.

All opaque byte fields and repeated collections carry the documented maximum in
the field comment. Runtime implementations must enforce those limits before
allocation and must authenticate the mTLS peer before accepting a request.

The API crate generates Rust message bindings with the pinned Prost toolchain and exposes the
compiled `FileDescriptorSet` for internal consumers. `openapi/generate-proto.mjs` generates the
TypeScript message, enum, oneof, and service metadata bindings from these same sources; run
`pnpm --dir crates/scoplen-api/openapi check-proto` to reject drift. The generated package is
available as `@scoplen/api/proto`. These bindings describe the wire contract only; concrete mTLS
gRPC service implementations remain a separate server workstream.
