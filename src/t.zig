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

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa = std.heap.DebugAllocator(.{
        .thread_safe = true,
    }){};
    defer _ = gpa.detectLeaks();

    const allocator = gpa.allocator();

    var userpass = Lookup.init(allocator);
    defer userpass.deinit();

    try userpass.put("zap", "awesome");

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

    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = on_request,
        .log = true,
    });

    try listener.listen();

    std.debug.print("Visit: http://127.0.0.1:3000\n", .{});
    std.debug.print("Username: zap\nPassword: awesome\n", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
