//! Zig JOSE/JWT verifier for identity-provider (M0).
//!
//! Mirrors the Rust `jose` crate against the shared vectors in
//! `testvectors/`. Only the strict base64url codec is present so far.

pub const b64url = @import("b64url.zig");

test {
    _ = b64url;
}
