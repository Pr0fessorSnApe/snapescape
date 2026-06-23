const std = @import("std");

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
    headers: std.StringHashMapUnmanaged([]const u8),
};

pub fn parseRequestLine(line: []const u8) !struct { method: []const u8, path: []const u8, version: []const u8 } {
    var it = std.mem.splitScalar(u8, line, ' ');
    const method = it.next() orelse return error.InvalidRequest;
    const path = it.next() orelse return error.InvalidRequest;
    const version = it.next() orelse return error.InvalidRequest;
    return .{ .method = method, .path = path, .version = version };
}

pub fn parseHeaders(data: []const u8, headers: *std.StringHashMapUnmanaged([]const u8)) !void {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, ":")) |idx| {
            const key = std.mem.trim(u8, line[0..idx], " \r");
            const val = std.mem.trim(u8, line[idx + 1 ..], " \r");
            try headers.put(std.heap.page_allocator, key, val);
        }
    }
}

pub fn extractParams(path: []const u8) std.StringHashMapUnmanaged([]const u8) {
    var params = std.StringHashMapUnmanaged([]const u8){};
    if (std.mem.indexOf(u8, path, "?")) |qidx| {
        const qs = path[qidx + 1 ..];
        var pairs = std.mem.splitScalar(u8, qs, '&');
        while (pairs.next()) |pair| {
            if (std.mem.indexOf(u8, pair, "=")) |eq| {
                params.put(std.heap.page_allocator, pair[0..eq], pair[eq + 1 ..]) catch {};
            }
        }
    }
    return params;
}
