# eBPF Enigma and Bombe Simulation

This project implements a virtual Enigma encryption machine and a Bombe decryption
device using eBPF. The system processes network packets in real-time, encrypting
outgoing traffic and attempting (using bombe) to decrypt incoming traffic.

## Demo

### Enigma Encryption in Action

[![asciicast](https://asciinema.org/a/T1fhwP4qnSwoRlr3DV929Omhf.svg)](https://asciinema.org/a/T1fhwP4qnSwoRlr3DV929Omhf)

### Bombe Decryption Attempt

[![asciicast](https://asciinema.org/a/YYT6AcA1nZuTT8dgqoWbZz1Ox.svg)](https://asciinema.org/a/YYT6AcA1nZuTT8dgqoWbZz1Ox)

## Prerequisites

- Linux kernel 5.17+ with eBPF support
- clang compiler
- bpftool
- netcat (nc)
- sudo privileges

## Setup Instructions

Follow these steps in order to set up and use the Enigma encryption system:

### 1. Network Setup

First, create the virtual network environment with two network namespaces:

```bash
make setup-network
```

This creates a network namespace called 'testns' and sets up a pair of virtual
ethernet interfaces (veth0 and veth1) connected to each other, with IP addresses
10.0.0.1 and 10.0.0.2 respectively.

#### Network Architecture

Below is a diagram of the system architecture showing how the Enigma and Bombe eBPF programs are deployed:

```
                              Network Communication
+----------------------+                                  +------------------------+
|                      |          veth pair               |                        |
| Host Namespace       |                                  | testns Namespace       |
|                      |                                  | (World / Allies' Side) |
|                      |    +-------------------+         |                        |
|                      |    |                   |         |                        |
|     [nc]             |    |                   |         |                        |
|       |              |    |                   |         |                        |
|       v              |    |                   |         |                        |
|    [veth0]-------------------------------------------------->[veth1]             |
|   10.0.0.1 |         |    |                   |         | | 10.0.0.2             |
|            |         |    |                   |         | |                      |
|     Enigma eBPF      |    |                   |         | Bombe eBPF             |
|     (egress)         |    |                   |         | (ingress)              |
|                      |    |                   |         |                        |
+----------------------+    +-------------------+         +------------------------+
    Encrypts outgoing                                      Attempts to decrypt
    plaintext traffic                                      incoming encrypted traffic
```

### 2. Build eBPF Programs

Compile the Enigma and Bombe eBPF programs:

```bash
make build
```

This compiles enigma.c and bombe.c into eBPF bytecode using clang.

### 3. Install eBPF Programs

Install the compiled eBPF programs to the network interfaces:

```bash
make install
```

This attaches the Enigma program to veth0's egress path and the Bombe program
to veth1's ingress path.

### 4. Pin BPF Maps

Pin the BPF maps so they can be accessed from userspace:

```bash
make pin-bombe-maps
```

This makes the rotor and reflector maps accessible at /sys/fs/bpf/tc/globals/.

### 5. Set Up Rotor and Reflector Maps

Configure the Enigma rotor and reflector settings:

```bash
make setup-maps
```

This initializes the rotors with the default configurations and ring settings
(AAA).

### 6. Reset Rotor Positions

Reset the rotor positions to their initial state:

```bash
make reset-rotors
```

This sets all rotors to position 0.

## Using the Enigma System

### Setting Up the Receiver

Before sending any messages, you need to set up a listener in the testns namespace
to receive the UDP traffic:

```bash
make start-receiver 
```

Or manually:

```bash
sudo ip netns exec testns nc -u -l -p 1912
```

Keep this terminal open while sending messages in another terminal.

### Encrypting Messages

To encrypt a message, send it via UDP to the virtual interface from your host
machine:

```bash
make send MSG="Hello World!"
```

Or manually:

```bash
echo -n "HELLO WORLD!" | nc -u -w1 -p 12345 10.0.0.2 1912
```

The message will be encrypted by the Enigma eBPF program as it passes through
veth0.

### Decrypting Messages

Decrypt the first message by resetting the rotors to the initial position and sending
the encrypted message:

```bash
make reset-rotors
echo -n "ILBDA QQDPF!" | nc -u -w1 -p 12345 10.0.0.2 1912
```

### Using the Bombe to Break Encryption

The Bombe component will attempt to crack the Enigma settings. Open a third terminal
window and monitor the trace pipe for successful decryption attempts:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

When the Bombe succeeds, it will print a message like:

```
Found! Run make set-rotor-position POS=35 R0=0 R1=1 R2=21 INPUT="<ENCRYPTED MSG>"
```

### Send Encrypted Messages for Bombe to Process

```bash
echo -n "HEUTE WIRD DAS WETTER SONNIG SEIN. EBPF ROCKS! ANGRIFF SUDEN AM NACHSTEN \
MORGEN" | nc -u -w1 -p 12345 10.0.0.2 1912
```

### Setting Rotor Positions

To manually set the rotor positions based on Bombe's output:

```bash
make set-rotor-position POS=35 R0=0 R1=1 R2=21 \
INPUT="GBTWT QCPO MFF DXJAYE PBJAKP AMAK. CQFO KITAK! CUBNYOL AFSZZ OQ POBJIKHQ QRQHUQ"
```

Parameters:
- POS: Starting position in the message to decode
- R0, R1, R2: Rotor positions for the three rotors
- INPUT: The encrypted message to decode

### Successfully Decrypted Message

After finding the correct rotor positions using the Bombe, you'll see the original
message in the receiver terminal:

```
EBPF ROCKS! ANGRIFF SUDEN AM NACHSTEN MORGEN
```

This confirms that the Bombe successfully broke the Enigma encryption and found the
correct settings to decrypt the message.

## Cleanup

When you're done, you can clean up in this order:

1. Uninstall the eBPF programs:
```bash
make uninstall
```

2. Remove the network setup:
```bash
make clean-network
```

3. Clean up the BPF maps:
```bash
make clean-maps
```

## Example Workflow

1. Set up the environment:
```bash
make setup-network build install pin-bombe-maps setup-maps reset-rotors
```

2. Start the UDP listener in a separate terminal:
```bash
sudo ip netns exec testns nc -u -l -p 1912
```

3. Encrypt a message:
```bash
echo -n "HELLO WORLD!" | nc -u -w1 -p 12345 10.0.0.2 1912
```

4. Reset the rotors to decrypt:
```bash
make reset-rotors
echo -n "ILBDA QQDPF!" | nc -u -w1 -p 12345 10.0.0.2 1912
```

5. Uninstall and clean up:
```bash
make uninstall clean-network clean-maps
```
