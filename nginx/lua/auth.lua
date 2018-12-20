local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OIDC_AUTH_METHOD") or "client_secret_basic",
    renew_access_token_on_expiry = os.getenv("OIDC_RENEW_ACCESS_TOKEN_ON_EXPIERY") ~= "false",
    scope = os.getenv("OIDC_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

-- call bearer_jwt_verify for OAuth 2.0 JWT validation
local res, err = require("resty.openidc").bearer_jwt_verify(opts)

ngx.log(ngx.INFO, tostring(res))
ngx.log(ngx.INFO, tostring(err))

if err or not res then
    ngx.status = 403
    ngx.say(err and err or "no access_token provided")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

ngx.log(ngx.INFO, "Authentication successful")