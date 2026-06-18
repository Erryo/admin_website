const std = @import("std");
const zap = @import("zap");

const Lookup = std.StringHashMap([]const u8);

const Authenticator = zap.Auth.UserPassSession(
    Lookup,
    false, // set true if userpass map changes at runtime
);

const loginpath = "/login";

var authenticator: Authenticator = undefined;

fn on_request(r: zap.Request) !void {
    switch (authenticator.authenticateRequest(&r)) {
        .Handled => {
            // Authenticator handled redirect/login/session logic.
            return;
        },

        .AuthFailed => unreachable,

        .AuthOK => {
            const path = r.path orelse "/";

            if (std.mem.startsWith(u8, path, loginpath)) {
                // serve page
            }

            if (std.mem.startsWith(u8, path, "/logout")) {
                // serve page;
            }

            return; // serve page
        },
    }
}
fn dispatch_routes(r: zap.Request) !void {
    // dispatch
    if (r.path) |the_path| {
        if (routes.get(the_path)) |foo| {
            try foo(r);
            return;
        }
    }
    // or default: present menu
    try r.sendBody();
}

fn handle_login(r: zap.Request) !void {
    _ = r;
}

fn setup_routes(a: std.mem.Allocator) !void {
    routes = std.StringHashMap(zap.HttpRequestFn).init(a);
    try routes.put("/login", handle_login);
}

var routes: std.StringHashMap(zap.HttpRequestFn) = undefined;

pub fn main() !void {
    try setup_routes(std.heap.page_allocator);
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = dispatch_routes,
        .log = true,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    zap.start(.{
        .threads = 2,
        .workers = 2,
    });
}
