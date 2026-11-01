//! Zig JOSE/JWT verifier for identity-provider (M0).
//!
//! Mirrors the Rust `jose` crate against the shared vectors in
//! `testvectors/`. Strict base64url and JSON parsing are present so far.

pub const b64url = @import("b64url.zig");
pub const json = @import("json.zig");

test {
    _ = b64url;
    _ = json;
}
