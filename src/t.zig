const std = @import("std");
const zap = @import("zap");

const Lookup = std.StringHashMap([]const u8);

const Authenticator = zap.Auth.UserPassSession(
    Lookup,
    false, // set true if userpass map changes at runtime
);

const loginpath = "/login";
const loginpage =
    \\<html>
    \\<body>
    \\  <form method="POST" action="/login">
    \\    <input name="username" placeholder="username">
    \\    <input name="password" type="password" placeholder="password">
    \\    <button type="submit">Login</button>
    \\  </form>
    \\</body>
    \\</html>
;

var authenticator: Authenticator = undefined;

fn on_login(r: zap.Request) !void {
    try r.sendBody(loginpage);
}

fn on_logout(r: zap.Request) !void {
    try r.sendBody(
        \\<html>
        \\<body>
        \\  <p>Logged out.</p>
        \\  <a href="/">Login again</a>
        \\</body>
        \\</html>
    );
}

fn on_protected_page(r: zap.Request) !void {
    try r.sendBody(
        \\<html>
        \\<body>
        \\  <h1>You are logged in</h1>
        \\  <a href="/logout">Logout</a>
        \\</body>
        \\</html>
    );
}

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
                return on_login(r);
            }

            if (std.mem.startsWith(u8, path, "/logout")) {
                return on_logout(r);
            }

            return on_protected_page(r);
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
