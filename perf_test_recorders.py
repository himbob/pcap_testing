import argparse
import os
import glob
import subprocess
import threading
import time
from scapy.all import rdpcap

def run_command(tool, iface):
    commands = {
        "tcpdump": f"tcpdump -i {iface} -v -Z root --immediate-mode --packet-buffered -B 131072 --time-stamp-precision=micro -w /data/tmp/{iface}.pcap -c 88888",
        "tshark": f"tshark -i {iface} -l -B 131072 -w /data/tmp/{iface}.pcap -q -c 888888888",
        "dumpcap": f"dumpcap -i {iface} -w /data/tmp/{iface}.pcap -a duration:8888888"
    }

    start_time = time.time()
    process = subprocess.Popen(commands[tool], shell=True)
    process.wait()
    end_time = time.time()

    return end_time - start_time

def capture_packets(tool, iface, results):
    duration = run_command(tool, iface)
    results[iface] = duration
    print(f"{tool} on {iface} took {duration} seconds to execute.")

def analyze_pcap(iface):
    pcap_file = f"/data/tmp/{iface}.pcap"
    pcap = rdpcap(pcap_file)
    packets_count = len(pcap)
    pcap_size = os.path.getsize(pcap_file)
    return packets_count, pcap_size

def flush_files():
    while True:
        time.sleep(5)
        os.system("sync")

def main(args):

    directory = "/data/tmp"
    extension = "*.pcap"

    files_to_delete = glob.glob(os.path.join(directory, extension))

    for file in files_to_delete:
        os.remove(file)

    interfaces = args.interfaces.split(',')
    tool = args.tool
    threads = []
    performance_results = {}

    try:
        for iface in interfaces:
            t = threading.Thread(target=capture_packets, args=(tool, iface, performance_results))
            threads.append(t)
            t.start()

        # flush every 5 seconds
        t = threading.Thread(target=flush_files)
        threads.append(t)
        t.start()

        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping packet capture.")

    finally:
        print("\nAnalysis Results:")
        for iface in interfaces:
            if os.path.exists(f"/data/tmp/{iface}.pcap"):
                packets_count, pcap_size = analyze_pcap(iface)
                print(f"Interface {iface}: {packets_count} packets captured, pcap size: {pcap_size} bytes")
            else:
                print(f"Interface {iface}: pcap file not found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Capture Performance Test")
    parser.add_argument("-i", "--interfaces", help="List of interfaces to monitor, separated by commas", required=True)
    parser.add_argument("-t", "--tool", help="Packet capture tool to use (tshark, tcpdump, or dumpcap)", choices=["tshark", "tcpdump", "dumpcap"], required=True)
    args = parser.parse_args()

    main(args)

