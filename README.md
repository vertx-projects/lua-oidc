# 基于openresty lua脚本实现OIDC

## 说明

扩展无感知token刷新能力，修改nginx.conf，修改项见：nginx.conf

此脚本依赖http模块，需要手动导入http_开头的3个lua包至：/usr/local/openresty/lualib/resty/

此脚本依赖核心环境变量如下，建议使用 **envsubst** 替换：

+ KEYCLOAK_CLIENT
+ KEYCLOAK_CLIENT_ID
+ KEYCLOAK2_INGRESS
+ KEYCLOAK_REALM
+ KEYCLOAK_REALM

---
其中 **KEYCLOAK** 代表一种实现了OIDC/OAuth2标准协议的身份认证及访问控制解决方案，也可以使用其他的