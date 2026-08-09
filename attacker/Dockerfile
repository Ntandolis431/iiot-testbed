# Attacker node (Task 3) — Kali Linux with Modbus/ICS attack tooling.
# Represents the "Attack Simulation" zone of the testbed architecture.
# For ISOLATED lab use only (see SECURITY.md).
#
# Build:  docker build -t iiot-attacker attacker/
# Run:    docker run -d --name kali --network iiot-net \
#           --cap-add=NET_ADMIN --cap-add=NET_RAW iiot-attacker
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      python3 python3-pip \
      ettercap-text-only \
      bettercap \
      hydra \
      hping3 \
      mosquitto-clients \
      tcpdump \
      iproute2 iputils-ping netcat-traditional curl \
 && pip3 install --break-system-packages pymodbus \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Keep the container alive so attack commands can be exec'd into it.
CMD ["sleep", "infinity"]
