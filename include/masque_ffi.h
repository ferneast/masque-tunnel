// MASQUE CONNECT-IP client FFI
// Based on RFC 9484 (Proxying IP in HTTP), for embedding in a host tunnel
// provider (iOS / tvOS / macOS NEPacketTunnelProvider).
//
// Lifecycle: the host creates the utun, passes a dup of its file descriptor to
// masque_client_ip_start (which takes ownership), and programs
// NEIPv4Settings / routes / DNS from the callbacks. All callbacks fire on the
// client's worker thread — host implementations must be thread-safe.

#pragma once

#include <stdbool.h>
#include <stdint.h>

// Log callback: level (0=error, 1=warn, 2=info, 3=debug/trace), message.
// Install once before masque_client_ip_start; must be callable from any thread
// and stay valid for the process lifetime.
typedef void (*masque_log_callback_t)(int32_t level, const char *message);
void masque_set_log_callback(masque_log_callback_t callback);

// Opaque handle for a running CONNECT-IP client.
typedef struct MasqueHandle MasqueHandle;

// Host callbacks. Function pointers and ctx must stay valid until
// masque_client_ip_stop returns.
typedef struct {
    void *ctx;
    // JSON array of assigned addresses (RFC 9484 ADDRESS_ASSIGN), the complete
    // current set: [{"addr":"10.99.0.2","prefix":32}, ...]
    void (*on_addresses)(void *ctx, const char *addrs_json);
    // JSON array of advertised routes expanded to CIDRs (ROUTE_ADVERTISEMENT),
    // the complete current set: [{"addr":"0.0.0.0","prefix":0,"proto":0}, ...]
    // proto: 0 = all protocols, otherwise an IANA Internet Protocol Number.
    void (*on_routes)(void *ctx, const char *routes_json);
    // state: 0 = connecting, 1 = established, 2 = error. detail may be NULL.
    void (*on_state)(void *ctx, int32_t state, const char *detail);
    // JSON array of DNS resolver addresses advertised by the proxy
    // (DNS_ASSIGN, draft-ietf-masque-connect-ip-dns): ["8.8.8.8", ...]
    // Called only when the proxy advertises DNS.
    void (*on_dns)(void *ctx, const char *dns_json);
} MasqueCallbacks;

// Starts the CONNECT-IP client. Reconnects internally with backoff until
// stopped; fatal setup errors surface via on_state(2, detail).
//   proxy_url:  MASQUE proxy URL, e.g. "https://relay.example.com" (required)
//   auth_token: Bearer token for proxy authorization (NULL = none)
//   sni:        TLS SNI override for domain fronting (NULL = host of proxy_url)
//   insecure:   skip server certificate verification (self-signed servers)
//   mtu:        TUN MTU; 0 selects the default (1280)
//   tun_fd:     dup of the provider's utun fd; the client takes ownership
// Returns an opaque handle, or NULL on invalid input.
MasqueHandle *masque_client_ip_start(const char *proxy_url,
                                     const char *auth_token,
                                     const char *sni,
                                     bool insecure,
                                     uint16_t mtu,
                                     int32_t tun_fd,
                                     MasqueCallbacks callbacks);

// Reads cumulative tunneled bytes since start (survives reconnects).
// Either out-pointer may be NULL. handle must be live (not yet stopped).
void masque_client_ip_stats(const MasqueHandle *handle,
                            uint64_t *tx_bytes,
                            uint64_t *rx_bytes);

// Hands the client a replacement TUN fd (a dup of the provider's current utun
// fd; the client takes ownership). Call after a tunnel-settings apply rebuilt
// the interface (macOS re-points the packet flow at a fresh utun, leaving the
// fd passed to start on a dead interface). The client swaps its forwarding
// device in place without dropping the QUIC connection. No-op for fd < 0.
// handle must be live (not yet stopped).
void masque_client_ip_update_tun_fd(const MasqueHandle *handle, int32_t tun_fd);

// Signals the client to drop its current connection and reconnect immediately,
// bypassing the QUIC idle-timeout wait. Call when the host detects a network
// path change (e.g. Wi-Fi <-> cellular). No-op if not running. handle must be
// live (not yet stopped).
void masque_client_ip_reconnect(const MasqueHandle *handle);

// Stops the client, joins its worker thread, and frees the handle.
// Call at most once per handle.
void masque_client_ip_stop(MasqueHandle *handle);
