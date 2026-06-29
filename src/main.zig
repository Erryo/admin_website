const std = @import("std");
const zap = @import("zap");
const log = std.log;

const ADMIN_password = "admin";
const ADMIN_username = "admin";

const loginpath = "/login";
const login_file_path = "static/login.html";
const admin_path = "/admin";

var allocator: std.mem.Allocator = undefined;
fn on_request(r: zap.Request) !void {
    const path = r.path orelse "/";
    r.parseCookies(false);

    if (std.mem.eql(u8, path, "/")) {
        try r.setContentType(.HTML);
        return try r.sendFile("static/index.html");
    }

    if (std.mem.eql(u8, path, loginpath)) {
        return try serve_login(r);
    }

    // Protected admin
    if (std.mem.startsWith(u8, path, admin_path)) {
        return try on_admin_req(r);
    }
}

fn on_admin_req(r: zap.Request) !void {
    if (try check_authed(r) == false) {
        try r.redirectTo("/login", .found);
        return;
    }

    dispatch_admin(r) catch |err| {
        log.err("dispatch failed: {}\n", .{err});
        return err;
    };
}

fn dispatch_admin(r: zap.Request) !void {
    errdefer {
        r.setStatus(.not_found);
        r.sendBody("404 Not Found") catch {};
    }
    const full_path = r.path orelse "/";

    const sub_path = full_path[admin_path.len..];

    // After successful login from form action="/admin"
    if (sub_path.len == 0 or std.mem.eql(u8, sub_path, "/")) {
        return try r.redirectTo("/admin/dashboard", .found);
    }

    if (admin_routes.get(sub_path)) |handler| {
        return try handler(r);
    }

    if (std.mem.indexOf(u8, sub_path, "..") != null) {
        r.setStatus(.forbidden);
        return try r.sendBody("403 Forbidden");
    }

    var path: []u8 = undefined;
    if (std.mem.indexOf(u8, sub_path, ".") != null) {
        path = try std.mem.concat(allocator, u8, &.{ "static", sub_path });
    } else {
        path = try std.mem.concat(allocator, u8, &.{ "static", sub_path, ".html" });
    }

    try r.sendFile(path);
}

fn check_authed(r: zap.Request) !bool {
    r.parseCookies(false);
    if (r.getCookiesCount() == 0) return false;
    const auth_cookie = try r.getCookieStr(allocator, "auth") orelse return false;
    defer allocator.free(auth_cookie);
    return true;
}

fn serve_login(r: zap.Request) !void {
    if (r.methodAsEnum() == .POST) {
        try get_login(r);
    } else {
        if (try check_authed(r)) {
            try r.redirectTo("/admin/", .found);
            return;
        }
        try r.setContentType(.HTML);
        try r.sendFile(login_file_path);
    }
}

fn get_login(r: zap.Request) !void {
    if (r.methodAsEnum() != .POST)
        return try r.sendBody("403 Forbidden");

    try r.parseBody();
    r.parseQuery();
    const param_count = r.getParamCount();
    log.info("param_count:{d}", .{param_count});
    if (param_count == 0) {
        return try r.sendBody("403 Forbidden");
    }

    const password_str = try r.getParamStr(allocator, "password") orelse {
        return try r.sendBody("403 Forbidden <br> <b> No password  </b>");
    };
    defer allocator.free(password_str);
    const username_str = try r.getParamStr(allocator, "username") orelse {
        return try r.sendBody("403 Forbidden <br> <b> No username  </b>");
    };
    defer allocator.free(username_str);
    log.info("username:{s} password:{s}", .{ username_str, password_str });

    if (std.mem.eql(u8, password_str, ADMIN_password) and std.mem.eql(u8, username_str, ADMIN_username)) {
        try r.setCookie(.{ .name = "auth", .value = "sig", .http_only = true, .secure = true, .path = "/" });
    }

    return r.redirectTo("/admin/", .found);
}

fn setup_routes(a: std.mem.Allocator) !void {
    admin_routes = std.StringHashMap(zap.HttpRequestFn).init(a);
}

var admin_routes: std.StringHashMap(zap.HttpRequestFn) = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    _ = io;

    var gpa = std.heap.DebugAllocator(.{
        .thread_safe = true,
    }){};

    defer {
        if (gpa.detectLeaks() != 0) @panic("detected leaks");
    }

    allocator = gpa.allocator();

    try setup_routes(std.heap.page_allocator);

    log.info("setup\n", .{});
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = on_request,
        .log = true,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    zap.start(.{
        .threads = 2,
        .workers = 2,
    });
}
