// enigma.c
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
} rotor1_map SEC(".maps"), rotor1_inv_map SEC(".maps"),
  rotor2_map SEC(".maps"), rotor2_inv_map SEC(".maps"),
  rotor3_map SEC(".maps"), rotor3_inv_map SEC(".maps"),
  reflector_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rotor_pos_map SEC(".maps");

// Accessors for each rotor/reflector
static __always_inline __u8 get_rotor1(__u32 idx)       { return get_val(&rotor1_map, idx); }
static __always_inline __u8 get_rotor1_inv(__u32 idx)   { return get_val(&rotor1_inv_map, idx); }
static __always_inline __u8 get_rotor2(__u32 idx)       { return get_val(&rotor2_map, idx); }
static __always_inline __u8 get_rotor2_inv(__u32 idx)   { return get_val(&rotor2_inv_map, idx); }
static __always_inline __u8 get_rotor3(__u32 idx)       { return get_val(&rotor3_map, idx); }
static __always_inline __u8 get_rotor3_inv(__u32 idx)   { return get_val(&rotor3_inv_map, idx); }
static __always_inline __u8 get_reflector(__u32 idx)    { return get_val(&reflector_map, idx); }

// Wrapper function around the common enigma_encrypt_char function
static __always_inline char encrypt_char(__u32 p0, __u32 p1, __u32 p2, char c) {
    return enigma_encrypt_char(
        get_rotor1, get_rotor2, get_rotor3,
        get_rotor1_inv, get_rotor2_inv, get_rotor3_inv,
        get_reflector,
        p0, p1, p2, c
    );
}

// Step rotors just like in the real Enigma (odometer style)
static __always_inline void step_rotors() {
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u32 *r0 = bpf_map_lookup_elem(&rotor_pos_map, &k0);
    __u32 *r1 = bpf_map_lookup_elem(&rotor_pos_map, &k1);
    __u32 *r2 = bpf_map_lookup_elem(&rotor_pos_map, &k2);

    if (!r0 || !r1 || !r2)
        return;

    // Double-stepping logic using common constants
    if (*r1 == NOTCH2) {
        *r0 = (*r0 + 1) % 26; // Step left rotor
        *r1 = (*r1 + 1) % 26; // Step middle rotor
    }
    if (*r2 == NOTCH3) {
        *r1 = (*r1 + 1) % 26; // Step middle rotor
    }

    *r2 = (*r2 + 1) % 26; // Step right rotor always moves
}

// Define context structure for the loop callback
struct loop_ctx {
    struct __sk_buff *skb;
    int payload_offset;
    int payload_len;
};

// Callback function for bpf_loop - declare prototype here
static int enigma_process_char(__u32 index, void *ctx_ptr);

// TC entrypoint
SEC("classifier")
int tc_enigma(struct __sk_buff *skb) {
    void *data_end, *data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    // Use common packet validation function
    if (!validate_packet(skb, &data, &data_end, &eth, &ip, &udp))
        return TC_ACT_OK;

    // Process the payload
    char *payload = (char *)(udp + 1);
    if ((void *)(payload + 1) > data_end)
        return TC_ACT_OK;

    // Calculate payload length using common function
    __u64 payload_len = calculate_payload_length(data, data_end, payload);
    if (payload_len == 0)
        return TC_ACT_OK;

    // Create a context structure to pass to the loop callback
    struct loop_ctx ctx = {
        .skb = skb,
        .payload_offset = (__u64)payload - (__u64)data,
        .payload_len = payload_len
    };

    // Use bpf_loop to process the payload
    bpf_loop(payload_len, (void *)enigma_process_char, &ctx, 0);

    return TC_ACT_OK;
}

static int enigma_process_char(__u32 i, void *ctx)
{
    struct loop_ctx *lctx = ctx;
    if (i >= lctx->payload_len)
        return 1; // stop

    step_rotors();

    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u32 *p0 = bpf_map_lookup_elem(&rotor_pos_map, &k0);
    __u32 *p1 = bpf_map_lookup_elem(&rotor_pos_map, &k1);
    __u32 *p2 = bpf_map_lookup_elem(&rotor_pos_map, &k2);

    if (!p0 || !p1 || !p2)
        return 1;

    unsigned char character = 0;
    bpf_skb_load_bytes(lctx->skb, lctx->payload_offset + i, &character, 1);

    character = encrypt_char(*p0, *p1, *p2, character);

    bpf_skb_store_bytes(lctx->skb, lctx->payload_offset + i, &character, 1, 0);

    return 0;
}