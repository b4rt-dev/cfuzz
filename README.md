# CFUZZ

A 802.11 fuzzer written in C using libpcap.

Contains the following files and directories:
- monitor.sh. Script to set Atheros dongle in monitor mode
- experiment 3. Contains the files for experiment 3
- experiment 4. Contains the files for experiment 4
- experiment 5. Contains the files for experiment 5
- BeaconSender. Contains python3 script for sending Beacon frames using a second dongle in monitor mode
- prbFuzzer. Contains the Probe response fuzzer
- authFuzzer. Contains the Authentication fuzzer
- assFuzzer. Contains the Association response fuzzer
- DSI. Contains a modified Probe response fuzzer to crash the Nintendo DSI XL
- README.md. This file