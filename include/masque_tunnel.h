/* C ABI for the masque-tunnel CONNECT-IP client (iOS / tvOS).
 *
 * Kept in sync with src/ffi.rs. `build-xcframework.sh` regenerates this with
 * cbindgen when it is installed; otherwise this checked-in copy is used. */
#ifndef MASQUE_TUNNEL_H
#define MASQUE_TUNNEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Host callbacks. Function pointers and `ctx` must stay valid until
 * masque_client_ip_stop() returns. They are invoked from the client's worker
 * thread, so the host implementation must be thread-safe. */
typedef struct MasqueCallbacks {
    void *ctx;
    /* JSON array: [{"addr":"10.99.0.2","prefix":32}, ...] */
    void (*on_addresses)(void *ctx, const char *addrs_json);
    /* JSON array: [{"start":"0.0.0.0","end":"255.255.255.255","proto":0}, ...] */
    void (*on_routes)(void *ctx, const char *routes_json);
    /* state: 0 = connecting, 1 = established, 2 = error; detail may be NULL */
    void (*on_state)(void *ctx, int32_t state, const char *detail);
} MasqueCallbacks;

/* Opaque handle owning the tunnel's worker thread. */
typedef struct MasqueHandle MasqueHandle;

/* Start the CONNECT-IP client against proxy_url, forwarding over tun_fd (a dup
 * of the NEPacketTunnelProvider utun fd — ownership is taken and it is closed
 * on stop). auth_token may be NULL. Returns NULL on invalid input. */
MasqueHandle *masque_client_ip_start(const char *proxy_url,
                                     const char *auth_token,
                                     int32_t tun_fd,
                                     MasqueCallbacks callbacks);

/* Stop the client and free the handle. Call once per handle. */
void masque_client_ip_stop(MasqueHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* MASQUE_TUNNEL_H */
