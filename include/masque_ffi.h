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
    // The tunnel dropped and auto_reconnect was false at start: the client is
    // holding until the host triggers the retry. Prepare the platform (set the
    // provider's reasserting = true) and call masque_client_ip_reconnect.
    // May also fire when the *initial* connect fails. Never called with
    // auto_reconnect true. detail carries the error text (never NULL).
    void (*on_retry)(void *ctx, const char *detail);
} MasqueCallbacks;

// Starts the CONNECT-IP client. Fatal setup errors surface via
// on_state(2, detail).
//   proxy_url:  MASQUE proxy URL, e.g. "https://relay.example.com" (required)
//   auth_token: Bearer token for proxy authorization (NULL = none)
//   extra_headers: operator-supplied headers for the CONNECT-IP request, one
//               "Name: Value" per line (NULL/empty = none), for proxies that
//               gate access on their own headers rather than a Bearer token.
//               The first entry of a given name replaces the header the client
//               would otherwise send under it (the auth_token-derived
//               proxy-authorization included); repeats of the same name are
//               appended. Lines without a colon, and names or values that are
//               not valid HTTP, are skipped with a warning.
//   sni:        TLS SNI override for domain fronting (NULL = host of proxy_url)
//   preferred_addresses: comma-separated preferred tunnel IPs to request on a
//               cold start, before any address is assigned, e.g.
//               "10.99.0.2,2001:db8::2" (NULL/empty/invalid = no preference).
//               The first entry of each family is used. A held address, kept
//               across reconnects, always takes precedence.
//   insecure:   skip server certificate verification (self-signed servers)
//   auto_reconnect: true = retry dropped tunnels internally with backoff;
//               false = each drop fires on_retry and the client holds until
//               masque_client_ip_reconnect (for hosts that must prepare the
//               platform first, e.g. an iOS provider entering reasserting)
//   mtu:        TUN MTU; 0 selects the default (1280)
//   tun_fd:     dup of the provider's utun fd; the client takes ownership
// Returns an opaque handle, or NULL on invalid input.
MasqueHandle *masque_client_ip_start(const char *proxy_url,
                                     const char *auth_token,
                                     const char *extra_headers,
                                     const char *sni,
                                     const char *preferred_addresses,
                                     bool insecure,
                                     bool auto_reconnect,
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

// Signals the client to reconnect immediately. With a tunnel up it drops the
// connection and redials at once, bypassing the QUIC idle-timeout wait — call
// on a network path change (e.g. Wi-Fi <-> cellular). After an on_retry
// (auto_reconnect false) it releases the held retry. No-op if not running.
// handle must be live (not yet stopped).
void masque_client_ip_reconnect(const MasqueHandle *handle);

// Stops the client, joins its worker thread, and frees the handle.
// Call at most once per handle.
void masque_client_ip_stop(MasqueHandle *handle);
