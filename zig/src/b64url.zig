//! Strict, unpadded base64url (RFC 4648 §5), as used by JOSE (RFC 7515 §2).
//!
//! The decoder matches the Rust `jose::b64url` rules and ADR 0003:
//! * only the URL-safe alphabet (`A-Z a-z 0-9 - _`);
//! * length congruent to 1 mod 4 is an error;
//! * unused trailing bits of the last character must be zero.
//!
//! Not constant-time. For token text, not secret key material.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub const DecodeError = error{
    InvalidCharacter,
    InvalidLength,
    NonCanonical,
    OutOfMemory,
};

/// Length of the unpadded base64url encoding of `n` bytes.
pub fn encodedLen(n: usize) usize {
    const rem: usize = switch (n % 3) {
        0 => 0,
        1 => 2,
        else => 3,
    };
    return (n / 3) * 4 + rem;
}

fn sextet(n: u32, shift: u5) u8 {
    return alphabet[@as(usize, @intCast((n >> shift) & 0x3f))];
}

/// Encodes `input` as unpadded base64url into a newly allocated slice.
pub fn encode(allocator: Allocator, input: []const u8) DecodeError![]u8 {
    const out = try allocator.alloc(u8, encodedLen(input.len));
    errdefer allocator.free(out);

    var oi: usize = 0;
    var i: usize = 0;
    while (i + 3 <= input.len) : (i += 3) {
        const n = (@as(u32, input[i]) << 16) | (@as(u32, input[i + 1]) << 8) | @as(u32, input[i + 2]);
        out[oi] = sextet(n, 18);
        out[oi + 1] = sextet(n, 12);
        out[oi + 2] = sextet(n, 6);
        out[oi + 3] = sextet(n, 0);
        oi += 4;
    }
    const rem = input.len - i;
    if (rem == 1) {
        const n = @as(u32, input[i]) << 16;
        out[oi] = sextet(n, 18);
        out[oi + 1] = sextet(n, 12);
    } else if (rem == 2) {
        const n = (@as(u32, input[i]) << 16) | (@as(u32, input[i + 1]) << 8);
        out[oi] = sextet(n, 18);
        out[oi + 1] = sextet(n, 12);
        out[oi + 2] = sextet(n, 6);
    }
    return out;
}

fn value(b: u8) ?u8 {
    return switch (b) {
        'A'...'Z' => b - 'A',
        'a'...'z' => b - 'a' + 26,
        '0'...'9' => b - '0' + 52,
        '-' => 62,
        '_' => 63,
        else => null,
    };
}

/// Decodes strict, canonical, unpadded base64url into a newly allocated slice.
/// The empty string decodes to an empty slice.
pub fn decode(allocator: Allocator, input: []const u8) DecodeError![]u8 {
    // Character check before length, matching Rust `jose::b64url::decode`.
    var vals = try allocator.alloc(u8, input.len);
    defer allocator.free(vals);
    for (input, 0..) |b, index| {
        vals[index] = value(b) orelse return error.InvalidCharacter;
    }
    if (vals.len % 4 == 1) return error.InvalidLength;

    const out_len = (vals.len / 4) * 3 + switch (vals.len % 4) {
        0 => @as(usize, 0),
        2 => 1,
        3 => 2,
        else => unreachable,
    };
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var oi: usize = 0;
    var i: usize = 0;
    while (i + 4 <= vals.len) : (i += 4) {
        const n = (@as(u32, vals[i]) << 18) |
            (@as(u32, vals[i + 1]) << 12) |
            (@as(u32, vals[i + 2]) << 6) |
            @as(u32, vals[i + 3]);
        out[oi] = @truncate(n >> 16);
        out[oi + 1] = @truncate(n >> 8);
        out[oi + 2] = @truncate(n);
        oi += 3;
    }
    const rem = vals.len - i;
    if (rem == 2) {
        if (vals[i + 1] & 0x0f != 0) return error.NonCanonical;
        out[oi] = (vals[i] << 2) | (vals[i + 1] >> 4);
    } else if (rem == 3) {
        if (vals[i + 2] & 0x03 != 0) return error.NonCanonical;
        const n = (@as(u32, vals[i]) << 10) | (@as(u32, vals[i + 1]) << 4) | (@as(u32, vals[i + 2]) >> 2);
        out[oi] = @truncate(n >> 8);
        out[oi + 1] = @truncate(n);
    }
    return out;
}

test "rfc4648 encode" {
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "", "" },
        .{ "f", "Zg" },
        .{ "fo", "Zm8" },
        .{ "foo", "Zm9v" },
        .{ "foob", "Zm9vYg" },
        .{ "fooba", "Zm9vYmE" },
        .{ "foobar", "Zm9vYmFy" },
    };
    for (cases) |c| {
        const encoded = try encode(testing.allocator, c[0]);
        defer testing.allocator.free(encoded);
        try testing.expectEqualStrings(c[1], encoded);
    }
}

test "rfc4648 decode" {
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "", "" },
        .{ "f", "Zg" },
        .{ "fo", "Zm8" },
        .{ "foo", "Zm9v" },
        .{ "foob", "Zm9vYg" },
        .{ "fooba", "Zm9vYmE" },
        .{ "foobar", "Zm9vYmFy" },
    };
    for (cases) |c| {
        const decoded = try decode(testing.allocator, c[1]);
        defer testing.allocator.free(decoded);
        try testing.expectEqualSlices(u8, c[0], decoded);
    }
}

test "url-safe alphabet is used" {
    const encoded = try encode(testing.allocator, &[_]u8{ 0xfb, 0xff });
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("-_8", encoded);
    const decoded = try decode(testing.allocator, "-_8");
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xfb, 0xff }, decoded);
}

test "rejects standard alphabet padding and whitespace" {
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "+_8"));
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "-/8"));
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "Zg=="));
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "Zm9v\n"));
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "Zm 9v"));
}

test "rejects length one mod four" {
    for ([_][]const u8{ "A", "Zm9vY", "Zm9vYmFyA" }) |s| {
        try testing.expectError(error.InvalidLength, decode(testing.allocator, s));
    }
}

test "rejects non-canonical trailing bits" {
    const f = try decode(testing.allocator, "Zg");
    defer testing.allocator.free(f);
    try testing.expectEqualSlices(u8, "f", f);
    for ([_][]const u8{ "Zh", "Zi", "Zj" }) |s| {
        try testing.expectError(error.NonCanonical, decode(testing.allocator, s));
    }
    const fo = try decode(testing.allocator, "Zm8");
    defer testing.allocator.free(fo);
    try testing.expectEqualSlices(u8, "fo", fo);
    try testing.expectError(error.NonCanonical, decode(testing.allocator, "Zm9"));
}

test "round trips every one and two byte input" {
    var a: u8 = 0;
    while (true) : (a +%= 1) {
        const one = [_]u8{a};
        const e1 = try encode(testing.allocator, &one);
        defer testing.allocator.free(e1);
        const d1 = try decode(testing.allocator, e1);
        defer testing.allocator.free(d1);
        try testing.expectEqualSlices(u8, &one, d1);

        var b: u8 = 0;
        while (true) : (b +%= 1) {
            const two = [_]u8{ a, b };
            const e2 = try encode(testing.allocator, &two);
            defer testing.allocator.free(e2);
            const d2 = try decode(testing.allocator, e2);
            defer testing.allocator.free(d2);
            try testing.expectEqualSlices(u8, &two, d2);
            if (b == 255) break;
        }
        if (a == 255) break;
    }
}

test "round trips all lengths with pseudo-random bytes" {
    var state: u32 = 0x1234_5678;
    const next = struct {
        fn call(s: *u32) u8 {
            s.* = s.* *% 1_664_525 +% 1_013_904_223;
            return @truncate(s.* >> 24);
        }
    }.call;

    var len: usize = 0;
    while (len <= 300) : (len += 1) {
        const data = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(data);
        for (data) |*byte| byte.* = next(&state);
        const encoded = try encode(testing.allocator, data);
        defer testing.allocator.free(encoded);
        try testing.expectEqual(encodedLen(len), encoded.len);
        const decoded = try decode(testing.allocator, encoded);
        defer testing.allocator.free(decoded);
        try testing.expectEqualSlices(u8, data, decoded);
    }
}

test "encoding is injective for two-byte inputs" {
    var a: u8 = 0;
    while (true) : (a +%= 1) {
        var b: u8 = 0;
        while (true) : (b +%= 1) {
            const s = try encode(testing.allocator, &[_]u8{ a, b });
            defer testing.allocator.free(s);
            const decoded = try decode(testing.allocator, s);
            defer testing.allocator.free(decoded);
            const again = try encode(testing.allocator, decoded);
            defer testing.allocator.free(again);
            try testing.expectEqualStrings(s, again);
            if (b == 255) break;
        }
        if (a == 255) break;
    }
}
