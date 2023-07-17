local client_id = "${KEYCLOAK_CLIENT}"
local scope = "openid%20profile%20microprofile-jwt"
local issuer_uri = "http://${KEYCLOAK2_INGRESS}/realms/${KEYCLOAK_REALM}"
local grant_type = "authorization_code"
local client_secret = "${KEYCLOAK_CLIENT_ID}"
local host = ngx.var.host
local port = tonumber("${PORT}")
if port and port ~= 80 then
    host = host .. ":" .. port
end
local redirect = { ngx.var.scheme, "://", host, ngx.var.uri }
local cache_map = ngx.shared.cache_map
function randonCode(length)
    local charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" -- specify the characters to choose from
    math.randomseed(os.time()) -- seed the random number generator
    local randomString = ""
    for _ = 1, length do
        local randomIndex = math.random(1, #charset) -- generate a random index within the range of the charset
        randomString = randomString .. string.sub(charset, randomIndex, randomIndex) -- append the randomly chosen character to the string
    end
    return randomString
end

-- 跳转登录页面
function login()
    local state = ngx.encode_base64(randonCode(32))
    ngx.header['Set-Cookie'] = { 'state=' .. state .. '; path=/; Expires=' .. ngx.cookie_time(ngx.time() + 60 * 30),
                                 'redirect=' .. table.concat(redirect) .. '; path=/; Expires=' .. ngx.cookie_time(ngx.time() + 60 * 30) }
    table.insert(redirect, "/login/oauth2/code/keycloak&state=")
    table.insert(redirect, state)
    local param = { issuer_uri, "/protocol/openid-connect/auth?response_type=code&client_id=", client_id, "&scope=", scope, "&redirect_uri=", table.concat(redirect) }
    local redirect_uri = table.concat(param)
    ngx.log(ngx.INFO, redirect_uri, 200)
    ngx.redirect(redirect_uri)
end
-- 验证code
function checkCode(code, response_state, session_state)
    local cookie_state = ngx.var.cookie_state
    if not cookie_state then
        ngx.log(ngx.ERR, "cookie state not valid reload login # ", 400)
        -- 跳转登录页面
        ngx.redirect(table.concat(redirect))
    end
    if cookie_state ~= response_state then
        ngx.log(ngx.ERR, "invalid state parameter # " .. response_state .. "#" .. cookie_state)
        ngx.exit(400)
    end
    local http = require("resty.http")
    local json = require("cjson.safe")
    local http_c = http.new()
    local basic = { client_id, ":", client_secret }
    local path = issuer_uri .. "/protocol/openid-connect/token"
    local body = { "grant_type=", grant_type, "&code=", code, "&redirect_uri=", table.concat(redirect) }
    local res, err = http_c:request_uri(path, {
        method = "POST",
        body = table.concat(body),
        headers = {
            ["Accept"] = "application/json;charset=UTF-8",
            ["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8",
            ["Authorization"] = "Basic " .. ngx.encode_base64(table.concat(basic))
        },
        keepalive_timeout = 60,
        keepalive_pool = 10
    })

    if err ~= nil then
        ngx.log(ngx.ERR, "login request_uri err = ", err)
        return ngx.exit(400)
    end

    if 200 ~= res.status then
        ngx.log(ngx.ERR, "login request status not 200#" .. res.body .. path, err)
        ngx.exit(res.status)
    end

    ngx.log(ngx.DEBUG, "login request body#", res.body)

    local v = json.decode(res.body)

    local access_token = v['access_token']
    local refresh_token = v['refresh_token']
    local id_token = v['id_token']
    cache_map:safe_set(session_state .. "_refresh", refresh_token)
    cache_map:safe_set(session_state .. "_access", access_token)
    cache_map:safe_set(session_state .. "_id", id_token)
    ngx.log(ngx.DEBUG, "id token # " .. id_token)
    local r = ngx.var.cookie_redirect
    ngx.header['Set-Cookie'] = { 'SESSION_ID=' .. session_state .. '; path=/; Expires=' .. ngx.cookie_time(ngx.time() + 60 * 30),
                                 'state=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()) }
    ngx.redirect(r);
end
-- 登出
function logoutCheck(session_id)
    local logout = redirect[4]
    if logout == "/logout" then
        redirect[4] = "/index.html"
        local uri = table.concat(redirect)
        ngx.log(ngx.ERR, "log out uri # " .. uri)
        local id_token = cache_map:get(session_id .. "_id")
        if not id_token then
            ngx.redirect(uri);
        end
        local path = issuer_uri .. "/protocol/openid-connect/logout?id_token_hint=" .. id_token .. "&post_logout_redirect_uri=" .. uri
        ngx.header['Set-Cookie'] = { 'SESSION_ID=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()), 'redirect=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()) }
        ngx.redirect(path);
    end
end
local args = ngx.req.get_uri_args()
local session_id = ngx.var.cookie_SESSION_ID
if not session_id then
    local code = args["code"]
    if not code then
        -- 跳转登录页面
        login()
    else
        local response_state = args["state"]
        local session_state = args["session_state"]
        -- 根据code发送http请求，获取id_token
        checkCode(code, response_state, session_state)
    end
else
    logoutCheck(session_id)
    -- 校验SESSION_ID是否存在
    local access_token = cache_map:get(ngx.var.cookie_SESSION_ID .. "_access")
    if not access_token then
        -- 清理无效Cookie
        ngx.header['Set-Cookie'] = { 'SESSION_ID=0; path=/; Expires=' .. ngx.cookie_time(ngx.time()) }
        -- 跳转登录页面
        ngx.redirect(table.concat(redirect))
    end
end
