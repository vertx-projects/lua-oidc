local issuer_uri = "http://${KEYCLOAK2_INGRESS}/realms/${KEYCLOAK_REALM}"
local client_secret = "${KEYCLOAK_CLIENT_ID}"
local client_id = "${KEYCLOAK_CLIENT}"
local json = require("cjson.safe")
local http = require("resty.http")
local http_c = http.new()
local cache_map = ngx.shared.cache_map
local headers = ngx.req.get_headers()

function introspectToken(access)
    --验证token
    local path = issuer_uri .. "/protocol/openid-connect/token/introspect"
    local body = { "token_type_hint=requesting_party_token&token=", access, "&client_id=", client_id, "&client_secret=", client_secret }
    local res, err = http_c:request_uri(path, {
        method = "POST",
        body = table.concat(body),
        headers = {
            ["Accept"] = "application/json;charset=UTF-8",
            ["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
        },
        keepalive_timeout = 60,
        keepalive_pool = 10
    })

    if err ~= nil then
        ngx.log(ngx.ERR, "introspect request err = ", err)
        return ngx.exit(400)
    end

    if 200 ~= res.status then
        ngx.log(ngx.ERR, "introspect request status not 200 # " .. res.body .. path, err)
        ngx.exit(res.status)
    end

    ngx.log(ngx.DEBUG, "introspect request body # ", res.body)
    local v = json.decode(res.body)
    return v['active']
end

function refreshToken(refresh)
    --验证token
    local path = issuer_uri .. "/protocol/openid-connect/token"
    local body = { "grant_type=refresh_token&refresh_token=", refresh, "&client_id=", client_id, "&client_secret=", client_secret }
    local res, err = http_c:request_uri(path, {
        method = "POST",
        body = table.concat(body),
        headers = {
            ["Accept"] = "application/json;charset=UTF-8",
            ["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
        },
        keepalive_timeout = 60,
        keepalive_pool = 10
    })

    if err ~= nil then
        ngx.log(ngx.ERR, "refresh token err = ", err)
        return ngx.exit(400)
    end

    if 200 ~= res.status then
        ngx.log(ngx.ERR, "refresh token not valid start redirect LOGIN #" .. res.body .. path, err)
        -- refresh token 失效，跳转回登录页
        local r = ngx.var.cookie_redirect
        ngx.header['Set-Cookie'] = { 'SESSION_ID=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()), 'redirect=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()) }
        ngx.redirect(r)
    end

    ngx.log(ngx.ERR, "refresh token success #", res.body)
    local v = json.decode(res.body)
    local access_token = v['access_token']
    if access_token then
        -- 刷新缓存 token
        cache_map:safe_set(ngx.var.cookie_SESSION_ID .. "_access", access_token)
        return access_token;
    end
end

function introspectAndRefreshToken()
    local refresh = cache_map:get(ngx.var.cookie_SESSION_ID .. "_refresh")
    local access = cache_map:get(ngx.var.cookie_SESSION_ID .. "_access")
    local active = introspectToken(access)

    ngx.log(ngx.DEBUG, "refresh token#" .. refresh)
    ngx.log(ngx.DEBUG, "setApiHeader string before:", json.encode(headers))

    if not active then
        -- 刷新token
        ngx.log(ngx.ERR, "access token not active start refresh token #", 301)
        access = refreshToken(refresh)
    else
        ngx.log(ngx.ERR, "access token active# ", 200)
    end

    ngx.req.set_header("Authorization", "Bearer " .. access)
    ngx.log(ngx.DEBUG, "setApiHeader string: after", json.encode(ngx.req.get_headers()))
end

if not headers.Authorization then
    introspectAndRefreshToken()
end
