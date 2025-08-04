# This Makefile uses bash substitution
SHELL := /bin/bash

# Variables for common commands and paths
CLANG = clang -O2 -g -target bpf -D__BPF_TRACING__ -Wall
TC_PATH = /sys/fs/bpf/tc/globals
VETH0 = veth0
VETH1 = veth1
NETNS = testns

# Define rotor configurations
ALPHAB = ABCDEFGHIJKLMNOPQRSTUVWXYZ
ROTOR1 = EKMFLGDQVZNTOWYHXUSPAIBRCJ
ROTOR2 = AJDKSIRUXBLHWTMCQGZNPYFVOE
ROTOR3 = BDFHJLCPRTXVZNYEIWGAKMUSQO
REFLECTOR = YRUHQSLDPXNGOKMIEBFZCWVJAT

# Define dependencies
COMMON_HEADER = enigma_common.h

.PHONY: build install uninstall setup-network clean-network reset-rotors setup-maps setup-rotors setup-reflector pin-bombe-maps clean-maps set-rotor-position

# Build BPF objects with explicit dependencies on common header
enigma.o: enigma.c $(COMMON_HEADER)
	$(CLANG) -c enigma.c -o enigma.o

bombe.o: bombe.c $(COMMON_HEADER)
	$(CLANG) -c bombe.c -o bombe.o

# Build BPF objects
build: enigma.o bombe.o

# Install BPF programs
install: uninstall build
	sudo tc qdisc add dev $(VETH0) clsact
	sudo tc filter add dev $(VETH0) egress bpf da obj enigma.o sec classifier
	sudo ip netns exec $(NETNS) tc qdisc add dev $(VETH1) clsact
	sudo ip netns exec $(NETNS) tc filter add dev $(VETH1) ingress bpf da obj bombe.o sec classifier

# Remove installed BPF programs
uninstall:
	sudo tc qdisc del dev $(VETH0) clsact 2>/dev/null || true
	sudo ip netns exec $(NETNS) tc qdisc del dev $(VETH1) clsact 2>/dev/null || true
	sudo rm -fr $(TC_PATH)/rotor_pos_map 2>/dev/null || true

# Network setup targets
setup-network: clean-network
	@echo "Creating network namespace and veth pairs"
	@sudo ip netns add $(NETNS)
	@sudo ip link add $(VETH0) type veth peer name $(VETH1)
	@sudo ip link set $(VETH1) netns $(NETNS)
	@sudo ip addr add 10.0.0.1/24 dev $(VETH0)
	@sudo ip link set $(VETH0) up
	@sudo ip netns exec $(NETNS) ip addr add 10.0.0.2/24 dev $(VETH1)
	@sudo ip netns exec $(NETNS) ip link set $(VETH1) up
	@echo "Network setup complete"

clean-network:
	@echo "Cleaning up network namespace and interfaces"
	@sudo ip link del $(VETH0) 2>/dev/null || true
	@sudo ip netns del $(NETNS) 2>/dev/null || true
	@echo "Network cleanup complete"

reset-rotors:
	sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 00 00 00 00 value hex 00 00 00 00
	sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 01 00 00 00 value hex 00 00 00 00
	sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 02 00 00 00 value hex 00 00 00 00

# Enigma machine setup targets
setup-maps: setup-rotors setup-reflector

setup-rotors:
	@echo "Setting up rotors with ring settings AAA"
	@$(MAKE) update-rotor1
	@$(MAKE) update-rotor2
	@$(MAKE) update-rotor3

# Update rotor maps
update-rotor1:
	@echo "Updating rotor1 maps"
	@./scripts/update_rotor.sh rotor1_map rotor1_inv_map "$(ROTOR1)" 1
	@./scripts/update_rotor.sh rotor1_bombe_map rotor1_inv_bombe_map "$(ROTOR1)" 1

update-rotor2:
	@echo "Updating rotor2 maps"
	@./scripts/update_rotor.sh rotor2_map rotor2_inv_map "$(ROTOR2)" 1
	@./scripts/update_rotor.sh rotor2_bombe_map rotor2_inv_bombe_map "$(ROTOR2)" 1

update-rotor3:
	@echo "Updating rotor3 maps"
	@./scripts/update_rotor.sh rotor3_map rotor3_inv_map "$(ROTOR3)" 1
	@./scripts/update_rotor.sh rotor3_bombe_map rotor3_inv_bombe_map "$(ROTOR3)" 1

setup-reflector:
	@echo "Setting up reflector"
	@./scripts/update_reflector.sh reflector_map "$(REFLECTOR)"
	@./scripts/update_reflector.sh reflector_bombe_map "$(REFLECTOR)"

# Set up rotor positions
set-rotor-position:
	@echo "Setting rotor positions to: [$(R0), $(R1), $(R2)]"
	@sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 00 00 00 00 value hex $(shell printf "%02x" $(R0)) 00 00 00
	@sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 01 00 00 00 value hex $(shell printf "%02x" $(R1)) 00 00 00
	@sudo bpftool map update pinned $(TC_PATH)/rotor_pos_map key hex 02 00 00 00 value hex $(shell printf "%02x" $(R2)) 00 00 00
	@echo "Rotor positions updated to [$(R0), $(R1), $(R2)]"
	@echo "Testing with input starting from position $(POS)"
	@export INPUT=$${INPUT:-TEST}; \
	echo "Original input: \"$$INPUT\""; \
	export TRUNCATED_INPUT=$$(echo -n "$$INPUT" | tail -c +$(shell expr $(POS) + 1)); \
	echo "Truncated input (removing first $(POS) chars): \"$$TRUNCATED_INPUT\""; \
	echo -n "$$TRUNCATED_INPUT" | nc -u -w1 -p 12345 10.0.0.2 1912

pin-bombe-maps:
	@echo "Pinning BPF maps..."
	@for map in rotor1_bombe_map rotor1_inv_bombe_map rotor2_bombe_map rotor2_inv_bombe_map rotor3_bombe_map rotor3_inv_bombe_map reflector_bombe_map; do \
		echo "Pinning map $$map..."; \
		sudo bpftool map pin name $${map:0:15} $(TC_PATH)/$$map 2>/dev/null || echo "Map $${map:0:15} not found"; \
	done

start-receiver:
       @echo "Starting receiver in network namespace $(NETNS)"
       @sudo ip netns exec $(NETNS) nc -u -l -p 1912

send:
       @echo "Sending message $${MSG^^} to receiver"
       @echo "$${MSG^^}" | sudo nc -u -w1 -p 12345 10.0.0.2 1912

clean-maps:
	@echo "Cleaning up BPF maps under $(TC_PATH)"
	@for i in $$(sudo find $(TC_PATH) -type f -name "*_map" 2>/dev/null); do \
		sudo rm -f $$i; \
		echo "Removed $$i"; \
	done
	@echo "BPF maps cleanup complete"

# Help target
help:
	@echo "Enigma/Bombe BPF Makefile"
	@echo ""
	@echo "Required Targets:"
	@echo "  setup-network      - Set up virtual network interfaces and namespace"
	@echo "  build              - Compile enigma.c and bombe.c to BPF objects"
	@echo "  install            - Install BPF programs after building"
	@echo "  pin-bombe-maps     - Pin BPF maps for bombe"
	@echo "  setup-maps         - Set up enigma rotor and reflector maps"
	@echo "  reset-rotors       - Reset rotor positions to initial state"
	@echo "  set-rotor-position - Set rotor positions (Usage: make set-rotor-position POS=29 R0=0 R1=1 R2=3)"
	@echo "  start-receiver     - Start the receiver in the network namespace"
	@echo "  send               - Send a message to the receiver (Usage: make send MSG=\"Hello World\")"
	@echo "  clean-network      - Clean up network namespace and interfaces"
	@echo "  uninstall          - Remove installed BPF programs"
	@echo "  clean-maps         - Clean up all BPF maps"
