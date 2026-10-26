//! A small, strict JSON parser (RFC 8259) for JOSE headers, claims and JWKS.
//!
//! Matches the Rust `jose::json` contract (ADR 0003):
//! * duplicate member names are an error at every nesting level, compared after
//!   unescaping;
//! * lone surrogates are an error;
//! * nesting deeper than `max_depth` is an error;
//! * plain integers that fit in `i64` are `Number.int`; every other number
//!   keeps its source text as `Number.other`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const max_depth: usize = 32;

pub const Number = union(enum) {
    int: i64,
    other: []u8,
};

pub const Value = union(enum) {
    null,
    bool: bool,
    number: Number,
    string: []u8,
    array: []Value,
    /// Members in source order. Names are unique (parser guarantee).
    object: []Member,

    pub const Member = struct {
        name: []u8,
        value: Value,
    };

    pub fn deinit(self: Value, allocator: Allocator) void {
        switch (self) {
            .null, .bool => {},
            .number => |n| switch (n) {
                .int => {},
                .other => |s| allocator.free(s),
            },
            .string => |s| allocator.free(s),
            .array => |items| {
                for (items) |item| item.deinit(allocator);
                allocator.free(items);
            },
            .object => |members| {
                for (members) |m| {
                    allocator.free(m.name);
                    m.value.deinit(allocator);
                }
                allocator.free(members);
            },
        }
    }

    pub fn asStr(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn asArray(self: Value) ?[]const Value {
        return switch (self) {
            .array => |a| a,
            else => null,
        };
    }

    pub fn asObject(self: Value) ?[]const Member {
        return switch (self) {
            .object => |o| o,
            else => null,
        };
    }

    pub fn asI64(self: Value) ?i64 {
        return switch (self) {
            .number => |n| switch (n) {
                .int => |i| i,
                .other => null,
            },
            else => null,
        };
    }

    pub fn get(self: Value, name: []const u8) ?*const Value {
        const members = self.asObject() orelse return null;
        for (members) |*m| {
            if (std.mem.eql(u8, m.name, name)) return &m.value;
        }
        return null;
    }
};

pub const JsonError = error{
    InvalidUtf8,
    UnexpectedEnd,
    Unexpected,
    InvalidString,
    TrailingData,
    DuplicateKey,
    TooDeep,
    OutOfMemory,
};

pub fn parse(allocator: Allocator, input: []const u8) JsonError!Value {
    if (!std.unicode.utf8ValidateSlice(input)) return error.InvalidUtf8;
    var parser = Parser{
        .allocator = allocator,
        .text = input,
        .pos = 0,
    };
    parser.skipWs();
    const value = try parser.parseValue(0);
    errdefer value.deinit(allocator);
    parser.skipWs();
    if (parser.pos != input.len) return error.TrailingData;
    return value;
}

const Parser = struct {
    allocator: Allocator,
    text: []const u8,
    pos: usize,

    fn peek(self: *const Parser) ?u8 {
        if (self.pos >= self.text.len) return null;
        return self.text[self.pos];
    }

    fn skipWs(self: *Parser) void {
        while (self.peek()) |b| {
            switch (b) {
                ' ', '\t', '\n', '\r' => self.pos += 1,
                else => return,
            }
        }
    }

    fn unexpected(self: *const Parser) JsonError {
        return if (self.peek() == null) error.UnexpectedEnd else error.Unexpected;
    }

    fn expect(self: *Parser, byte: u8) JsonError!void {
        if (self.peek() == byte) {
            self.pos += 1;
        } else {
            return self.unexpected();
        }
    }

    fn literal(self: *Parser, word: []const u8, value: Value) JsonError!Value {
        if (self.pos + word.len <= self.text.len and std.mem.eql(u8, self.text[self.pos..][0..word.len], word)) {
            self.pos += word.len;
            return value;
        }
        const rest = self.text[self.pos..];
        var matched: usize = 0;
        while (matched < rest.len and matched < word.len and rest[matched] == word[matched]) : (matched += 1) {}
        self.pos += matched;
        return self.unexpected();
    }

    fn parseValue(self: *Parser, depth: usize) JsonError!Value {
        return switch (self.peek() orelse return self.unexpected()) {
            '{' => self.object(depth),
            '[' => self.array(depth),
            '"' => .{ .string = try self.string() },
            't' => self.literal("true", .{ .bool = true }),
            'f' => self.literal("false", .{ .bool = false }),
            'n' => self.literal("null", .null),
            '-', '0'...'9' => self.number(),
            else => self.unexpected(),
        };
    }

    fn object(self: *Parser, depth: usize) JsonError!Value {
        if (depth >= max_depth) return error.TooDeep;
        try self.expect('{');
        var members: std.ArrayListUnmanaged(Value.Member) = .{};
        errdefer {
            for (members.items) |m| {
                self.allocator.free(m.name);
                m.value.deinit(self.allocator);
            }
            members.deinit(self.allocator);
        }

        self.skipWs();
        if (self.peek() == '}') {
            self.pos += 1;
            return .{ .object = try members.toOwnedSlice(self.allocator) };
        }

        while (true) {
            self.skipWs();
            if (self.peek() != '"') return self.unexpected();
            const name = try self.string();
            var name_owned = true;
            errdefer if (name_owned) self.allocator.free(name);
            self.skipWs();
            try self.expect(':');
            self.skipWs();
            const value = try self.parseValue(depth + 1);
            var value_owned = true;
            errdefer if (value_owned) value.deinit(self.allocator);

            for (members.items) |m| {
                if (std.mem.eql(u8, m.name, name)) return error.DuplicateKey;
            }
            try members.append(self.allocator, .{ .name = name, .value = value });
            name_owned = false;
            value_owned = false;

            self.skipWs();
            switch (self.peek() orelse return self.unexpected()) {
                ',' => self.pos += 1,
                '}' => {
                    self.pos += 1;
                    return .{ .object = try members.toOwnedSlice(self.allocator) };
                },
                else => return self.unexpected(),
            }
        }
    }

    fn array(self: *Parser, depth: usize) JsonError!Value {
        if (depth >= max_depth) return error.TooDeep;
        try self.expect('[');
        var items: std.ArrayListUnmanaged(Value) = .{};
        errdefer {
            for (items.items) |item| item.deinit(self.allocator);
            items.deinit(self.allocator);
        }

        self.skipWs();
        if (self.peek() == ']') {
            self.pos += 1;
            return .{ .array = try items.toOwnedSlice(self.allocator) };
        }

        while (true) {
            self.skipWs();
            const value = try self.parseValue(depth + 1);
            var value_owned = true;
            errdefer if (value_owned) value.deinit(self.allocator);
            try items.append(self.allocator, value);
            value_owned = false;
            self.skipWs();
            switch (self.peek() orelse return self.unexpected()) {
                ',' => self.pos += 1,
                ']' => {
                    self.pos += 1;
                    return .{ .array = try items.toOwnedSlice(self.allocator) };
                },
                else => return self.unexpected(),
            }
        }
    }

    fn digits(self: *Parser) JsonError!void {
        const start = self.pos;
        while (self.peek()) |b| {
            switch (b) {
                '0'...'9' => self.pos += 1,
                else => break,
            }
        }
        if (self.pos == start) return self.unexpected();
    }

    fn number(self: *Parser) JsonError!Value {
        const start = self.pos;
        if (self.peek() == '-') self.pos += 1;
        switch (self.peek() orelse return self.unexpected()) {
            '0' => self.pos += 1,
            '1'...'9' => try self.digits(),
            else => return self.unexpected(),
        }
        var integral = true;
        if (self.peek() == '.') {
            integral = false;
            self.pos += 1;
            try self.digits();
        }
        if (self.peek()) |b| {
            if (b == 'e' or b == 'E') {
                integral = false;
                self.pos += 1;
                if (self.peek()) |s| {
                    if (s == '+' or s == '-') self.pos += 1;
                }
                try self.digits();
            }
        }
        const lexeme = self.text[start..self.pos];
        if (integral) {
            if (std.fmt.parseInt(i64, lexeme, 10)) |n| {
                return .{ .number = .{ .int = n } };
            } else |_| {}
        }
        const owned = try self.allocator.dupe(u8, lexeme);
        return .{ .number = .{ .other = owned } };
    }

    fn hex4(self: *Parser) JsonError!u32 {
        if (self.pos + 4 > self.text.len) return error.UnexpectedEnd;
        var n: u32 = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            const b = self.text[self.pos];
            const d: u32 = switch (b) {
                '0'...'9' => b - '0',
                'a'...'f' => b - 'a' + 10,
                'A'...'F' => b - 'A' + 10,
                else => return error.InvalidString,
            };
            n = (n << 4) | d;
            self.pos += 1;
        }
        return n;
    }

    fn unicodeEscape(self: *Parser) JsonError!u21 {
        const at = self.pos;
        const first = try self.hex4();
        const code: u32 = switch (first) {
            0xD800...0xDBFF => blk: {
                if (self.pos + 2 > self.text.len or !std.mem.eql(u8, self.text[self.pos .. self.pos + 2], "\\u")) {
                    return error.InvalidString;
                }
                self.pos += 2;
                const second = try self.hex4();
                if (second < 0xDC00 or second > 0xDFFF) return error.InvalidString;
                break :blk 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            },
            0xDC00...0xDFFF => return error.InvalidString,
            else => first,
        };
        _ = at;
        return std.math.cast(u21, code) orelse error.InvalidString;
    }

    fn string(self: *Parser) JsonError![]u8 {
        try self.expect('"');
        var out: std.ArrayListUnmanaged(u8) = .{};
        errdefer out.deinit(self.allocator);

        while (true) {
            const b = self.peek() orelse return error.UnexpectedEnd;
            switch (b) {
                '"' => {
                    self.pos += 1;
                    return try out.toOwnedSlice(self.allocator);
                },
                '\\' => {
                    self.pos += 1;
                    const esc = self.peek() orelse return error.UnexpectedEnd;
                    self.pos += 1;
                    switch (esc) {
                        '"', '\\', '/' => try out.append(self.allocator, esc),
                        'b' => try out.append(self.allocator, 0x08),
                        'f' => try out.append(self.allocator, 0x0C),
                        'n' => try out.append(self.allocator, '\n'),
                        'r' => try out.append(self.allocator, '\r'),
                        't' => try out.append(self.allocator, '\t'),
                        'u' => {
                            const cp = try self.unicodeEscape();
                            var buf: [4]u8 = undefined;
                            const len = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidString;
                            try out.appendSlice(self.allocator, buf[0..len]);
                        },
                        else => return error.InvalidString,
                    }
                },
                0x00...0x1F => return error.InvalidString,
                else => {
                    // Consume one UTF-8 codepoint's leading byte sequence by
                    // advancing one byte; full UTF-8 validity was checked up front.
                    try out.append(self.allocator, b);
                    self.pos += 1;
                },
            }
        }
    }
};

test "parses scalars" {
    const a = testing.allocator;
    {
        const v = try parse(a, "null");
        defer v.deinit(a);
        try testing.expect(v == .null);
    }
    {
        const v = try parse(a, "true");
        defer v.deinit(a);
        try testing.expectEqual(true, v.bool);
    }
    {
        const v = try parse(a, "false");
        defer v.deinit(a);
        try testing.expectEqual(false, v.bool);
    }
    {
        const v = try parse(a, "0");
        defer v.deinit(a);
        try testing.expectEqual(@as(i64, 0), v.asI64().?);
    }
    {
        const v = try parse(a, "-0");
        defer v.deinit(a);
        try testing.expectEqual(@as(i64, 0), v.asI64().?);
    }
    {
        const v = try parse(a, "1700000000");
        defer v.deinit(a);
        try testing.expectEqual(@as(i64, 1_700_000_000), v.asI64().?);
    }
    {
        const v = try parse(a, "\"abc\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("abc", v.asStr().?);
    }
    {
        const v = try parse(a, "\"\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("", v.asStr().?);
    }
}

test "parses the rfc 7515 a1 header" {
    const a = testing.allocator;
    const v = try parse(a, "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
    defer v.deinit(a);
    try testing.expectEqualStrings("JWT", v.get("typ").?.asStr().?);
    try testing.expectEqualStrings("HS256", v.get("alg").?.asStr().?);
    try testing.expect(v.get("kid") == null);
}

test "parses nested structures and keeps member order" {
    const a = testing.allocator;
    const v = try parse(a, "{\"b\":[1,2,{\"c\":null}],\"a\":{\"x\":true}}");
    defer v.deinit(a);
    const members = v.asObject().?;
    try testing.expectEqualStrings("b", members[0].name);
    try testing.expectEqualStrings("a", members[1].name);
    const arr = v.get("b").?.asArray().?;
    try testing.expectEqual(@as(i64, 1), arr[0].asI64().?);
    try testing.expect(arr[2].get("c").?.* == .null);
}

test "allows json whitespace only" {
    const a = testing.allocator;
    const v = try parse(a, " \t\r\n[ 1 , 2 ]\n");
    defer v.deinit(a);
    const arr = v.asArray().?;
    try testing.expectEqual(@as(i64, 1), arr[0].asI64().?);
    try testing.expectEqual(@as(i64, 2), arr[1].asI64().?);
    try testing.expectError(error.Unexpected, parse(a, "\u{000B}1"));
    try testing.expectError(error.Unexpected, parse(a, "\u{00A0}1"));
    try testing.expectError(error.Unexpected, parse(a, "\u{FEFF}1"));
}

test "rejects duplicate keys" {
    const a = testing.allocator;
    try testing.expectError(error.DuplicateKey, parse(a, "{\"alg\":\"EdDSA\",\"alg\":\"none\"}"));
    try testing.expectError(error.DuplicateKey, parse(a, "{\"a\":{\"b\":1,\"b\":2}}"));
    try testing.expectError(error.DuplicateKey, parse(a, "[{\"k\":1,\"k\":1}]"));
    try testing.expectError(error.DuplicateKey, parse(a, "{\"a\":1,\"\\u0061\":2}"));
    try testing.expectError(error.DuplicateKey, parse(a, "{\"a/b\":1,\"a\\/b\":2}"));
    {
        const v = try parse(a, "{\"a\":1,\"A\":2,\"a \":3}");
        defer v.deinit(a);
    }
    {
        const v = try parse(a, "{\"a\":{\"x\":1},\"b\":{\"x\":2},\"c\":[{\"x\":3},{\"x\":4}]}");
        defer v.deinit(a);
    }
}

test "decodes escapes and utf8" {
    const a = testing.allocator;
    {
        const v = try parse(a, "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("\"\\/\u{8}\u{c}\n\r\t", v.asStr().?);
    }
    {
        const v = try parse(a, "\"\\u00e9\\u00E9\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("éé", v.asStr().?);
    }
    {
        const v = try parse(a, "\"\\u0000\"");
        defer v.deinit(a);
        try testing.expectEqual(@as(usize, 1), v.asStr().?.len);
        try testing.expectEqual(@as(u8, 0), v.asStr().?[0]);
    }
    {
        const v = try parse(a, "\"é€😀\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("é€😀", v.asStr().?);
    }
    {
        const v = try parse(a, "{\"é\":\"ü\"}");
        defer v.deinit(a);
        try testing.expectEqualStrings("ü", v.get("é").?.asStr().?);
    }
    {
        const v = try parse(a, "\"\\ud83d\\ude00\"");
        defer v.deinit(a);
        try testing.expectEqualStrings("😀", v.asStr().?);
    }
}

test "rejects bad strings and grammar" {
    const a = testing.allocator;
    for ([_][]const u8{ "\"\\ud83d\"", "\"\\ud83dx\"", "\"\\ud83d\\u0041\"", "\"\\ude00\"", "\"\\ude00\\ud83d\"" }) |s| {
        try testing.expectError(error.InvalidString, parse(a, s));
    }
    for ([_][]const u8{ "\"\\x41\"", "\"\\u12G4\"", "\"\\u12\"", "\"a\nb\"", "\"a\tb\"", "\"\u{1}\"", "\"\\q\"" }) |s| {
        const result = parse(a, s);
        try testing.expect(result == error.InvalidString or result == error.Unexpected or result == error.UnexpectedEnd);
    }
    try testing.expectError(error.UnexpectedEnd, parse(a, ""));
    try testing.expectError(error.UnexpectedEnd, parse(a, "\"abc"));
    for ([_][]const u8{
        "{,}", "[,]", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "{'a':1}", "[1 2]",
        "{\"a\":1 \"b\":2}", "nul", "True", "NULL", "undefined", "NaN", "Infinity",
        "// c\n1", "/* c */1", "[1]]", "{}}",
    }) |s| {
        if (parse(a, s)) |v| {
            v.deinit(a);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "rejects trailing data and strict numbers" {
    const a = testing.allocator;
    try testing.expectError(error.TrailingData, parse(a, "1 2"));
    try testing.expectError(error.TrailingData, parse(a, "{} {}"));
    for ([_][]const u8{ "01", "-01", "00", "+1", ".5", "1.", "-", "-.5", "1e", "1e+", "1.e3", "0x10", "1_000", "- 1", "--1" }) |s| {
        if (parse(a, s)) |v| {
            v.deinit(a);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "only plain integers are ints" {
    const a = testing.allocator;
    {
        const v = try parse(a, "42");
        defer v.deinit(a);
        try testing.expectEqual(@as(i64, 42), v.asI64().?);
    }
    {
        const v = try parse(a, "-42");
        defer v.deinit(a);
        try testing.expectEqual(@as(i64, -42), v.asI64().?);
    }
    {
        const v = try parse(a, "9223372036854775807");
        defer v.deinit(a);
        try testing.expectEqual(std.math.maxInt(i64), v.asI64().?);
    }
    {
        const v = try parse(a, "-9223372036854775808");
        defer v.deinit(a);
        try testing.expectEqual(std.math.minInt(i64), v.asI64().?);
    }
    for ([_][]const u8{ "9223372036854775808", "1.0", "1.5", "1e3", "1E3", "1e-3", "-0.0", "10e0" }) |s| {
        const v = try parse(a, s);
        defer v.deinit(a);
        try testing.expect(v.asI64() == null);
        try testing.expectEqualStrings(s, v.number.other);
    }
}

test "accessors do not coerce types" {
    const a = testing.allocator;
    {
        const v = try parse(a, "\"1\"");
        defer v.deinit(a);
        try testing.expect(v.asI64() == null);
    }
    {
        const v = try parse(a, "1");
        defer v.deinit(a);
        try testing.expect(v.asStr() == null);
    }
    {
        const v = try parse(a, "[]");
        defer v.deinit(a);
        try testing.expect(v.asObject() == null);
    }
    {
        const v = try parse(a, "{}");
        defer v.deinit(a);
        try testing.expect(v.asArray() == null);
    }
}

test "rejects invalid utf8" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidUtf8, parse(a, &[_]u8{ '"', 0xff, '"' }));
    try testing.expectError(error.InvalidUtf8, parse(a, &[_]u8{ '"', 0xc3, '"' }));
    try testing.expectError(error.InvalidUtf8, parse(a, &[_]u8{ '"', 0xc0, 0xaf, '"' }));
    try testing.expectError(error.InvalidUtf8, parse(a, &[_]u8{ '"', 0xed, 0xa0, 0x80, '"' }));
}

test "nesting limit is exact" {
    const a = testing.allocator;
    {
        const nested = try a.alloc(u8, max_depth * 2);
        defer a.free(nested);
        @memset(nested[0..max_depth], '[');
        @memset(nested[max_depth..], ']');
        const v = try parse(a, nested);
        defer v.deinit(a);
    }
    {
        const nested = try a.alloc(u8, (max_depth + 1) * 2);
        defer a.free(nested);
        @memset(nested[0 .. max_depth + 1], '[');
        @memset(nested[max_depth + 1 ..], ']');
        try testing.expectError(error.TooDeep, parse(a, nested));
    }
    {
        // {"a": repeated max_depth times then 1 then }
        var list: std.ArrayListUnmanaged(u8) = .{};
        defer list.deinit(a);
        var i: usize = 0;
        while (i < max_depth) : (i += 1) try list.appendSlice(a, "{\"a\":");
        try list.append(a, '1');
        i = 0;
        while (i < max_depth) : (i += 1) try list.append(a, '}');
        const v = try parse(a, list.items);
        defer v.deinit(a);
    }
    {
        var list: std.ArrayListUnmanaged(u8) = .{};
        defer list.deinit(a);
        var i: usize = 0;
        while (i < max_depth + 1) : (i += 1) try list.appendSlice(a, "{\"a\":");
        try list.append(a, '1');
        i = 0;
        while (i < max_depth + 1) : (i += 1) try list.append(a, '}');
        try testing.expectError(error.TooDeep, parse(a, list.items));
    }
}

test "deeply nested hostile input does not overflow the stack" {
    const a = testing.allocator;
    const deep = try a.alloc(u8, 1_000_000);
    defer a.free(deep);
    @memset(deep, '[');
    try testing.expectError(error.TooDeep, parse(a, deep));
}

test "handles many members and long strings" {
    const a = testing.allocator;
    {
        var body: std.ArrayListUnmanaged(u8) = .{};
        defer body.deinit(a);
        try body.append(a, '{');
        var i: usize = 0;
        while (i < 2000) : (i += 1) {
            if (i > 0) try body.append(a, ',');
            var buf: [32]u8 = undefined;
            const piece = try std.fmt.bufPrint(&buf, "\"k{d}\":{d}", .{ i, i });
            try body.appendSlice(a, piece);
        }
        try body.append(a, '}');
        const v = try parse(a, body.items);
        defer v.deinit(a);
        try testing.expectEqual(@as(usize, 2000), v.asObject().?.len);
        try testing.expectEqual(@as(i64, 1999), v.get("k1999").?.asI64().?);
    }
    {
        const long = try a.alloc(u8, 100_000);
        defer a.free(long);
        @memset(long, 'x');
        var quoted: std.ArrayListUnmanaged(u8) = .{};
        defer quoted.deinit(a);
        try quoted.append(a, '"');
        try quoted.appendSlice(a, long);
        try quoted.append(a, '"');
        const v = try parse(a, quoted.items);
        defer v.deinit(a);
        try testing.expectEqualSlices(u8, long, v.asStr().?);
    }
}

