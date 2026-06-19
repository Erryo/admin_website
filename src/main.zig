const std = @import("std");
const zap = @import("zap");
const log = std.log;

const Lookup = std.StringHashMap([]const u8);

const Authenticator = zap.Auth.UserPassSession(
    Lookup,
    false, // set true if userpass map changes at runtime
);

const ADMIN_password = "admin";
const ADMIN_username = "admin";

const loginpath = "/login";
const login_file_path = "static/login.html";
const admin_path = "/admin";

var allocator: std.mem.Allocator = undefined;
var authenticator: Authenticator = undefined;
fn on_request(r: zap.Request) !void {
    const path = r.path orelse "/";

    if (std.mem.eql(u8, path, "/")) {
        try r.setContentType(.HTML);
        return try r.sendFile("static/index.html");
    }

    // Login page: DO NOT authenticate this route.
    // UserPassSession always lets loginPage through.
    if (std.mem.eql(u8, path, loginpath)) {
        return try serve_login(r);
    }

    // Protected admin
    if (std.mem.startsWith(u8, path, admin_path)) {
        return try on_admin_req(r);
    }
}

fn on_admin_req(r: zap.Request) !void {
    switch (authenticator.authenticateRequest(&r)) {
        .Handled => {
            // Authenticator handled redirect/login/session logic.
            return;
        },
        .AuthFailed => unreachable, //This Authenticator never return this
        .AuthOK => { // Logged in
            dispatch_admin(r) catch |err| {
                log.err("dispatch failed: {}\n", .{err});
                return err;
            };
        },
    }
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

fn serve_login(r: zap.Request) !void {
    try r.setContentType(.HTML);
    try r.sendFile(login_file_path);
}

fn setup_routes(a: std.mem.Allocator) !void {
    admin_routes = std.StringHashMap(zap.HttpRequestFn).init(a);
}

var admin_routes: std.StringHashMap(zap.HttpRequestFn) = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa = std.heap.DebugAllocator(.{
        .thread_safe = true,
    }){};

    defer {
        if (gpa.detectLeaks() != 0) @panic("detected leaks");
    }

    allocator = gpa.allocator();

    var userpass = Lookup.init(allocator);
    defer userpass.deinit();

    try userpass.put(ADMIN_username, ADMIN_password);

    authenticator = try Authenticator.init(
        io,
        allocator,
        &userpass,
        .{
            .usernameParam = "username",
            .passwordParam = "password",
            .loginPage = loginpath,
            .cookieName = "zap-session",
        },
    );
    defer authenticator.deinit();
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
