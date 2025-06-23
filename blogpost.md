# Breaking Boundaries: Implementing the Enigma Machine in eBPF

Today we are marking the celebration of Alan Turing's 113th birthday by
implementing the Enigma machine in eBPF. The Enigma machine was not developed
by Turing himself, but it was the machine he famously broke during World War II.

## The Historical Enigma and Turing's Legacy

The Enigma machine was an encryption device developed in the early 20th century
and famously used by Nazi Germany during World War II to encrypt their military
communications. The machine's seemingly unbreakable encryption posed a
significant challenge to the Allied forces. There were many variants of the
machine, but they all shared a common design: a keyboard, a set of rotating
scrambling wheels (rotors) that scrambled letters, a plugboard to scramble the
letters even more, and a lampboard that displayed the encrypted output.

Alan Turing, a British mathematician and logician, played a crucial role in
the British version of the Bombe machine, which was designed to break the
Enigma's encrypted messages. The Bombe was specifically designed to find
the daily settings, i.e., the setup of the rotors that were used during the 24
hours. After finding the daily settings, many messages could be
manually decrypted. This breakthrough is estimated to have shortened World
War II by two to four years, potentially saving millions of lives.

Turing's work on breaking the Enigma machine laid foundational principles for
modern computing and artificial intelligence. His concepts of computation and
the famous "Turing machine" established the theoretical groundwork that
underpins all modern computers and algorithms.

## My Journey with eBPF: A Decade in the Making

Although I've been indirectly involved in eBPF since its beginning about 10
years ago, I personally found it practically impossible to develop using this
technology due to the verifier being notoriously difficult to work with. In the
early days, you'd frequently encounter cryptic errors like this monstrous output
from a simple change:

```
Join EP id=29898 ifname=lxcd7915

Prog section 'from-container' rejected: Permission denied (13)!
 - Type:         3
 - Instructions: 3276 (0 over limit)
 - License:      GPL

Verifier analysis:

Skipped 18658 bytes, use 'verb' option for the full verbose log.
[...]
r1
112: (15) if r2 == 0x0 goto pc+9
 R0=inv R1=inv63 R2=inv R3=imm2 R6=ctx R7=imm0 R8=inv R9=inv48 R10=fp
113: (b7) r1 = 2
114: (63) *(u32 *)(r6 +48) = r1
115: (63) *(u32 *)(r6 +52) = r8
116: (bf) r1 = r6
117: (18) r2 = 0x14b75f00
119: (b7) r3 = 2
120: (85) call 12
121: safe

from 112 to 122: safe

[... hundreds of similar register operations omitted ...]

1580: (61) r1 = *(u32 *)(r10 -136)
1581: (55) if r1 != 0xdf0 goto pc+104
 R0=inv R1=inv R6=ctx R7=imm0 R8=inv R9=inv48 R10=fp
1582: (61) r1 = *(u32 *)(r10 -132)
1583: (67) r1 <<= 32
1584: (77) r1 >>= 32

[... more operations omitted ...]

1640: (7b) *(u64 *)(r10 -152) = r0
1641: (15) if r0 == 0x0 goto pc-1539
 R0=map_value(ks=4,vs=104) R6=ctx R7=imm2 R8=inv R9=inv48 R10=fp fp-152=map_value_or_null
1642: (79) r2 = *(u64 *)(r10 -152)
1643: (79) r1 = *(u64 *)(r2 +8)
R2 invalid mem access 'map_value_or_null'

Error fetching program/map!
Failed to retrieve (e)BPF data!
```

With complexity limits of just 4,096 instructions, even simple programs would
fail verification. The verifier would output thousands of lines of assembly-like
instructions with register states and jump targets that made little sense to
anyone except the most dedicated kernel developers. These error messages were
challenging to decipher, ironically similar to the challenge of breaking an
Enigma-encrypted message itself. You practically needed to be Alan Turing to
make sense of what was going wrong! That's why I left eBPF to more talented
engineers with deeper kernel expertise and decided to focus my efforts on
Cilium's control plane, which was written in Golang <3

That's why, a decade after first encountering eBPF, I decided to take on the
challenge to see how much the tooling had improved, approaching it as a complete
novice. What better way to test this than by implementing the very encryption
machine that Turing himself worked to crack?

The first brick wall I hit was my old nemesis: the verifier, which greeted me
with this "friendly" error:

```
; unsigned int i = c - 'A'; @ prog.c:42
53: (0f) r9 += r1                     ; R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0x1ffffffff))
; i = (i + *p0) % 26; @ prog.c:44
54: (07) r9 += -65                    ; R9_w=scalar(smin=0,smax=umax=0x100000018,var_off=(0x0; 0x1ffffffff))
55: (67) r9 <<= 32                    ; R9_w=scalar(smax=0x7fffffff00000000,umax=0xffffffff00000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffff00000000))
56: (77) r9 >>= 32                    ; R9_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
57: (97) r9 %= 26                     ; R9_w=scalar()
; i = array[i]; @ prog.c:46
58: (18) r3 = 0xffff9d3592696f08      ; R3_w=map_value(map=prog.rodata,ks=4,vs=156)
60: (0f) r3 += r9

math between map_value pointer and register with unbounded min value is not allowed
```

The errors might look similarly cryptic, but at least they're more focused and
specific now, pointing to the exact line in my source code where the problem
occurred. Still, it wasn't exactly obvious what was going wrong.

Fortunately, I had the perk of being friends with the eBPF co-creator, so I
simply dropped him a question: "Hey Daniel, is this a verifier bug or what?" (Of
course, the problem was between the chair and the keyboard). He replied: "Ah,
the compiler is optimizing away the `if (i < 0 || i >= 26) return c;` since it
knows you did modulo." And I thought, "Great, now I have to fight against the
compiler as well..." I decided to shelve it for the next day.

When I returned to the project, I discovered something that every developer
loves: documentation! I'm kidding... I read up on how to use `bpf_printk`, which
helped me tremendously in understanding what I was doing wrong.

After a couple of days, I successfully implemented cipher and decipher
functionality for messages. By messages, I mean UDP packets that I could send
and receive using `nc`. Unfortunately, I noticed my implementation wasn't
matching the original Enigma, or at least not matching the results of other
Enigma machine emulators I found online.

After diving into Wikipedia pages on the Enigma machine, reading countless
blogs, and watching videos about its mechanics, I discovered my implementation
had a subtle but critical bug. In one of the videos describing Enigma's
behavior, I had assumed the rotors would rotate *after* the electrical signal
passed through them. It turns out the rotors actually rotate *before* the
electrical signal is sent. Once I fixed this subtle detail, my implementation
finally matched other Enigma emulators.

This journey reminded me of Turing's own persistence when trying to decrypt
Enigma messages. The modern challenges I faced with the eBPF verifier pale in
comparison to what Turing and his team had to overcome with minimal resources
and the pressure of war.

## The Enigma Machine in eBPF

My eBPF implementation captures all the key components of the original Enigma
machine "Enigma I" with three rotors (I, II, III) from 1930 and a reflector
(Reflector B).

1. **Rotors and Reflectors** - Implemented using BPF maps, these simulate the
   mechanical rotors that performed the encryption in the physical Enigma
   machine. Each rotor is essentially a scrambled alphabet - press 'A' and it
   might connect to 'R', while 'B' might connect to 'F':

```
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
```

2. **Character Processing** - For each character, the eBPF code simulates the
   electrical signal passing through the rotors, reflector, and back through the
   rotors - just like the physical machine:

```
// Encrypt a single uppercase character
static __always_inline char enigma_encrypt_char(__u32 p0, __u32 p1, __u32 p2, char c) {
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
```

3. **Rotor Stepping** - My implementation includes the complex "double-stepping"
   behavior of the physical Enigma's mechanical rotors:

```
// Step rotors just like in the real Enigma (odometer style)
static __always_inline void step_rotors() {
    // Define notch positions (example: rotor1=Q, rotor2=E, rotor3=V)
    const __u32 notch2 = 4;  // E
    const __u32 notch3 = 21; // V

    // Double-stepping logic
    if (*r1 == notch2) {
        *r0 = (*r0 + 1) % 26; // Step left rotor
        *r1 = (*r1 + 1) % 26; // Step middle rotor
    }
    if (*r2 == notch3) {
        *r1 = (*r1 + 1) % 26; // Step middle rotor
    }

    *r2 = (*r2 + 1) % 26; // Step right rotor
}
```

Here we can see an asciinema show the Enigma machine in action, encrypting and
decrypting. The message is sent over UDP, the eBPF program processes it, and
encrypts the message on "egress". The receiver then receives the encrypted
message. To decrypt it, the receiver sets the rotor positions to the same
positions as the sender. If we send the encrypted message, we can then decrypt
it. The sender and receiver must agree on the rotor positions beforehand, which
was shared through a pre-arranged table.

https://asciinema.org/a/T1fhwP4qnSwoRlr3DV929Omhf

## Bonus: A "not-to-be-named Bombe" in eBPF

The Enigma machine implementation was straightforward, but as an Allied
codebreaker, we also need to implement the Bombe. After researching the Bombe
more deeply, I realized that implementing it in eBPF would be a significant
challenge. The original Bombe wasn't designed for naive brute-force attacks,
but rather for targeted searches using logical deductions based on cribs
(known plaintext fragments).

Given the Bombe's complexity, I opted to implement a simplified version.
Interestingly, my simplified Bombe only works on kernels 5.17 and later, as
it relies on `bpf_loop()` to iterate through all possible rotor positions.
This makes the code surprisingly simple while demonstrating something that
would have been extraordinarily complex in earlier versions of eBPF:

```
   for (int i = 0; i <= lctx->payload_len - crib_len; i++) {
        // [...]
        if (match) {
            p0 = idx / (26 * 26);
            p1 = (idx / 26) % 26;
            p2 = (idx % 26);
            bpf_printk("Found! Run make set-rotor-position POS=%d R0=%d R1=%d R2=%d INPUT=\"<ENCRYPTED MSG>\"", i, p0, p1, p2);
            return 1; // Stop the loop
        }
    }
```

With the Bombe implemented, we can now run it against the encrypted messages
to find the rotor positions used for encryption. This allows us to decrypt
messages by finding the position of a "crib" (a known plaintext fragment). In
our example, we know the nazis used the expression "EBPF ROCK". We don't know
where it is in the message, but we can search for it. The Bombe will iterate
through all possible rotor positions and check if the decrypted message contains
the encrypted crib. If it finds a match, it will print the rotor positions
needed to decrypt the message and the position of the crib in the message.

To decrypt the message, we can then run the Enigma machine with the found rotor
positions and the position of the crib. The Enigma machine will then decrypt it.

https://asciinema.org/a/YYT6AcA1nZuTT8dgqoWbZz1Ox

Success! We were able to decrypt the message using the Bombe, and the Allies
will have a significant advantage in winning the war!

## From Breaking Codes to Breaking Boundaries

On June 23rd, 2025, as we celebrate Alan Turing's 113th birthday and his
revolutionary contributions to computing, my eBPF implementation of the Enigma
machine serves as both a technical demonstration and a personal tribute to his
genius.

The evolution of eBPF over the past decade, from a limited packet filter to a
Turing-complete system capable of implementing complex encryption algorithms,
demonstrates the same innovative spirit that Turing embodied. Today, writing
eBPF programs is more accessible than ever. So much so that anyone can experiment
and build even the silliest things, like an Enigma machine or something as
simple as a "dumb" Bombe. What Turing accomplished with paper, pencils, and
early electromechanical computers, we can now do within the Linux kernel itself.
