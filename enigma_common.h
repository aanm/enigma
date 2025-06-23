// enigma_common.h
// Common definitions for Enigma encryption and Bombe decryption
#ifndef ENIGMA_COMMON_H
#define ENIGMA_COMMON_H

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

// Common license declaration
#define ENIGMA_LICENSE char LICENSE[] SEC("license") = "GPL"

// Define MAX_PAYLOAD_SIZE for payload length calculations
#define MAX_PAYLOAD_SIZE 1472

// Define notch positions (used by both enigma and bombe)
#define NOTCH2 4  // E
#define NOTCH3 21 // V

// Process a character through a rotor - macro used by both implementations
#define PROCESS_ROTOR(get_rotor, p, i) \
    i = (get_rotor((i + p) % 26) - p + 26) % 26

// Common helper to get a value from a map
static __always_inline __u8 get_val(void *map, __u32 idx) {
    __u32 k = idx % 26;
    __u8 *v = bpf_map_lookup_elem(map, &k);
    return v ? *v : 0;
}

// Common UDP port for Enigma traffic
#define ENIGMA_UDP_PORT 0x7807 // Port 1912 - 30727 in network byte order

// Common packet validation for TC programs
static __always_inline int validate_packet(struct __sk_buff *skb, void **data_ptr, void **data_end_ptr,
                                          struct ethhdr **eth_ptr, struct iphdr **ip_ptr, struct udphdr **udp_ptr) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    // Check IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->protocol != IPPROTO_UDP)
        return 0;

    // Check UDP header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return 0;

    // Check if it's our target port
    if (udp->dest != ENIGMA_UDP_PORT)
        return 0;

    *data_ptr = data;
    *data_end_ptr = data_end;
    *eth_ptr = eth;
    *ip_ptr = ip;
    *udp_ptr = udp;

    return 1;
}

// Calculate payload length safely
static __always_inline __u64 calculate_payload_length(void *data, void *data_end, void *payload) {
    __u64 payload_offset = (__u64)payload - (__u64)data;
    __u64 data_len = (__u64)data_end - (__u64)data;

    if (payload_offset >= data_len)
        return 0;

    __u64 payload_len = data_len - payload_offset;
    return (payload_len > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : payload_len;
}

// Encrypt a single uppercase character - common implementation for both enigma and bombe
static __always_inline char enigma_encrypt_char(
    __u8 (*get_rotor1)(__u32),
    __u8 (*get_rotor2)(__u32),
    __u8 (*get_rotor3)(__u32),
    __u8 (*get_rotor1_inv)(__u32),
    __u8 (*get_rotor2_inv)(__u32),
    __u8 (*get_rotor3_inv)(__u32),
    __u8 (*get_reflector)(__u32),
    __u32 p0, __u32 p1, __u32 p2, char c) {

    if (c < 'A' || c > 'Z')
        return c;

    __u32 i = c - 'A';

    // Forward pass through the rotors
    PROCESS_ROTOR(get_rotor3, p2, i);
    PROCESS_ROTOR(get_rotor2, p1, i);
    PROCESS_ROTOR(get_rotor1, p0, i);

    // Hit the reflector
    i = get_reflector(i);

    // Backward pass through the inverse rotors
    PROCESS_ROTOR(get_rotor1_inv, p0, i);
    PROCESS_ROTOR(get_rotor2_inv, p1, i);
    PROCESS_ROTOR(get_rotor3_inv, p2, i);

    return i + 'A';
}

#endif /* ENIGMA_COMMON_H */
