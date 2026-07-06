const std = @import("std");
const zap = @import("zap");
const log = std.log;

const ADMIN_password = "admin";
const ADMIN_username = "admin";

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Base64URLSafeEncoder = std.base64.url_safe_no_pad.Encoder;
const Base64URLSafeDecoder = std.base64.url_safe_no_pad.Decoder;
var secret_key = "zkrlTATcp3WBg5ABYTBD3OcQPoMeF-dBs5x9Xxu648mNkEBvylLzk8jE9QNst59zH5YsB_iT_M2iONeXUWY1p2pdbsHG3y4tf309_KvN3pnCkAAIN2Rolnhz40Gku6Q8SS21g_OEynqbK45UjD5_MWC9CmyLb02Dn1FvBmFaYx15GXKKEy3yWPobLumc-VQklb5uEIqKGiyMkQ55vCzyDMNuPKEQ1c6YkP_IZO2FNSy9Z4Z6xsuleCFe5PePJRPm";

const loginpath = "/login";
const login_file_path = "static/login.html";
const admin_path = "/admin";
const JWT_HEADER_ascii =
    \\             {
    \\  "alg": "HS256",
    \\  "typ": "JWT"
    \\ }
;

const JWT_HEADER_b64url = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
var current_id: ?[128:0]u8 = null;
var allocator: std.mem.Allocator = undefined;
var io: ?std.Io = null;

// user needs to free returned slice
fn encode_b64url(data: []const u8) ![]const u8 {
    const req_len = Base64URLSafeEncoder.calcSize(data.len);
    const buff = try allocator.alloc(u8, req_len);
    errdefer allocator.free(buff);
    const encoded = Base64URLSafeEncoder.encode(buff, data);
    return encoded;
}

fn make_jwt(new_val: bool) ![]const u8 {
    if (new_val) {
        if (io == null) return error.NoIo;
        current_id = std.mem.zeroes([128:0]u8);
        io.?.random(&current_id.?);
    }
    const encoded_id = try encode_b64url(&current_id.?);
    defer allocator.free(encoded_id);
    // header + .+ base64({ "auth": + current_id + }) + . + base64(signature)
    const json = try std.fmt.allocPrint(allocator, "{{\"auth\":\"{s}\"}}", .{encoded_id});
    defer allocator.free(json);
    const json_b64 = try encode_b64url(json);
    defer allocator.free(json_b64);

    const sign_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ JWT_HEADER_b64url, json_b64 });
    defer allocator.free(sign_input);

    const signature = try sign(sign_input);

    const sig_b64 = try encode_b64url(&signature);
    defer allocator.free(sig_b64);

    const token = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ sign_input, sig_b64 });
    return token;
}

fn verify(data: []const u8) !bool {
    if (current_id == null) {
        log.info("current_id is null \n", .{});
        return false;
    }
    var iter = std.mem.splitAny(u8, data, ".");
    var header: ?[]const u8 = null;
    var body: ?[]const u8 = null;
    var signature: ?[]const u8 = null;
    while (iter.next()) |slice| {
        if (slice.len == 0 or std.mem.eql(u8, slice, "")) continue;
        if (header == null) {
            header = slice;
        } else if (body == null) {
            body = slice;
        } else if (signature == null) {
            signature = slice;
        }
    }

    if (header == null or body == null or signature == null) {
        log.info("headr/bdy/sig is null: h:{},b:{},s:{}\n", .{ header == null, body == null, signature == null });
        return false;
    }

    const encoded_id = try encode_b64url(&current_id.?);
    defer allocator.free(encoded_id);
    // header + .+ base64({ "auth": + current_id + }) + . + base64(signature)
    const json = try std.fmt.allocPrint(allocator, "{{\"auth\":\"{s}\"}}", .{encoded_id});
    defer allocator.free(json);
    const json_b64 = try encode_b64url(json);
    defer allocator.free(json_b64);

    const sign_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ JWT_HEADER_b64url, json_b64 });
    defer allocator.free(sign_input);

    const calc_signature: [HmacSha256.mac_length]u8 = try sign(sign_input);

    const sig_b64 = try encode_b64url(&calc_signature);
    defer allocator.free(sig_b64);

    std.log.info("\n\n\tsoll: {s} \tist:{s}\n", .{ sig_b64, signature.? });
    if (!std.mem.eql(u8, sig_b64, signature.?)) return false;

    return true;
}

fn sign(data: []const u8) ![HmacSha256.mac_length]u8 {
    var buff: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&buff, data, secret_key);
    return buff;
}

fn decode_b64url(data: []const u8) ![]const u8 {
    const req_len = try Base64URLSafeDecoder.calcSizeForSlice(data);
    const buff = try allocator.alloc(u8, req_len);
    errdefer allocator.free(buff);
    Base64URLSafeDecoder.decode(buff, data) catch |err| {
        if (err == error.NoSpaceLeft) {
            const max_len = try Base64URLSafeDecoder.calcSizeUpperBound(data.len);
            const buff_max = try allocator.alloc(u8, max_len);
            errdefer allocator.free(buff_max);
            try Base64URLSafeDecoder.decode(buff_max, data);

            allocator.free(buff);
            return buff_max;
        } else {
            return err;
        }
    };
    return buff;
}

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
    const passed = try verify(auth_cookie);
    log.info("check:{}\n", .{passed});
    return passed;
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
        const jwt = try make_jwt(true);
        defer allocator.free(jwt);
        try r.setCookie(.{ .name = "auth", .value = jwt, .http_only = true, .secure = true, .path = "/" });
    }

    return r.redirectTo("/admin/", .found);
}

fn setup_routes(a: std.mem.Allocator) !void {
    admin_routes = std.StringHashMap(zap.HttpRequestFn).init(a);
}

var admin_routes: std.StringHashMap(zap.HttpRequestFn) = undefined;

pub fn main(init: std.process.Init) !void {
    io = init.io;

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
