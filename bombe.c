// bombe.c
#include "enigma_common.h"

// Use the common license declaration
ENIGMA_LICENSE;

// Maps for rotors, inverse rotors, reflector, and rotor positions
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 26);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rotor1_bombe_map SEC(".maps"), rotor1_inv_bombe_map SEC(".maps"),
  rotor2_bombe_map SEC(".maps"), rotor2_inv_bombe_map SEC(".maps"),
  rotor3_bombe_map SEC(".maps"), rotor3_inv_bombe_map SEC(".maps"),
  reflector_bombe_map SEC(".maps");

// Accessors for each rotor/reflector
static __always_inline __u8 get_rotor1(__u32 idx)       { return get_val(&rotor1_bombe_map, idx); }
static __always_inline __u8 get_rotor1_inv(__u32 idx)   { return get_val(&rotor1_inv_bombe_map, idx); }
static __always_inline __u8 get_rotor2(__u32 idx)       { return get_val(&rotor2_bombe_map, idx); }
static __always_inline __u8 get_rotor2_inv(__u32 idx)   { return get_val(&rotor2_inv_bombe_map, idx); }
static __always_inline __u8 get_rotor3(__u32 idx)       { return get_val(&rotor3_bombe_map, idx); }
static __always_inline __u8 get_rotor3_inv(__u32 idx)   { return get_val(&rotor3_inv_bombe_map, idx); }
static __always_inline __u8 get_reflector(__u32 idx)    { return get_val(&reflector_bombe_map, idx); }

// Wrapper function around the common enigma_encrypt_char function
static __always_inline char encrypt_char(__u32 p0, __u32 p1, __u32 p2, char c) {
    return enigma_encrypt_char(
        get_rotor1, get_rotor2, get_rotor3,
        get_rotor1_inv, get_rotor2_inv, get_rotor3_inv,
        get_reflector,
        p0, p1, p2, c
    );
}

struct loop_ctx {
    unsigned char *payload;
    void *data_end;
    int payload_len;
};

// Bombe callback function - tries to find matching rotors positions by brute force
static __always_inline int bombe_callback(__u32 idx, void *ctx) {
    char crib[] = "EBPF ROCK";
    int crib_len = sizeof(crib) - 1;
    struct loop_ctx *lctx = ctx;
    char encrypted[crib_len];

    // Initial rotor positions for this idx
    __u32 p0 = (idx / (26 * 26)) % 26;
    __u32 p1 = (idx / 26) % 26;
    __u32 p2 = idx % 26;

    for (int i = 0; i < crib_len; i++) {
        // Double-stepping logic using common constants
        if (p1 == NOTCH2) {
            p0 = (p0 + 1) % 26; // Step left rotor
            p1 = (p1 + 1) % 26; // Step middle rotor
        }
        if (p2 == NOTCH3) {
            p1 = (p1 + 1) % 26; // Step middle rotor
        }
        p2 = (p2 + 1) % 26; // Step right rotor always moves

        encrypted[i] = encrypt_char(p0, p1, p2, crib[i]);
    }

    // Compare encrypted crib with payload
    // Only search within the valid payload length
    for (int i = 0; i <= lctx->payload_len - crib_len; i++) {
        int match = 1;
        for (int j = 0; j < crib_len; j++) {
            unsigned char *p = lctx->payload + i + j;
            if (p >= (unsigned char *)lctx->data_end) {
                bpf_printk("Match NOT found! Stopping... Data end reached.");
                return 1; // stop
            }
            if (encrypted[j] != *p) {
                match = 0;
                break;
            }
        }
        if (match) {
            p0 = idx / (26 * 26);
            p1 = (idx / 26) % 26;
            p2 = (idx % 26);
            bpf_printk("Found! Run make set-rotor-position POS=%d R0=%d R1=%d R2=%d INPUT=\"<ENCRYPTED MSG>\"", i, p0, p1, p2);
            return 1; // Stop the loop
        }
    }

    return 0; // Continue the loop
}

// Brute force search for rotor positions
static __always_inline int bombe(void *ctx) {
    __u32 max_iterations = 26 * 26 * 26;
    bpf_loop(max_iterations, bombe_callback, ctx, 0);
    return 0;
}

// TC entrypoint
SEC("classifier")
int tc_bombe(struct __sk_buff *skb) {
    void *data_end, *data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    // Use common packet validation function
    if (!validate_packet(skb, &data, &data_end, &eth, &ip, &udp))
        return TC_ACT_OK;

    // Process the payload
    unsigned char *payload = (unsigned char *)(udp + 1);
    if ((void *)(payload + 1) > data_end)
        return TC_ACT_OK;

    // Calculate payload length using common function
    __u64 payload_len = calculate_payload_length(data, data_end, payload);
    if (payload_len == 0)
        return TC_ACT_OK;

    // Create a context structure to pass to the loop callback
    struct loop_ctx lctx = {
        .payload = payload,
        .data_end = data_end,
        .payload_len = payload_len
    };
    bombe(&lctx);
    return TC_ACT_OK;
}