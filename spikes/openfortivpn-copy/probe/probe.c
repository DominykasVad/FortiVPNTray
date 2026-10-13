// Does what openfortivpn does first with OpenSSL: create a context and load the default trust paths.
// The three functions are declared here so that no OpenSSL headers are needed to build it.
#include <stdio.h>
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
const SSL_METHOD *TLS_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);

int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    int paths = ctx ? SSL_CTX_set_default_verify_paths(ctx) : -1;
    printf("SSL_CTX_new: %s, set_default_verify_paths: %d\n", ctx ? "ok" : "failed", paths);
    return ctx ? 0 : 1;
}
