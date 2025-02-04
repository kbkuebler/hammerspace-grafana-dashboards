#!/usr/bin/env python3
import sys

def prompt_list(prompt_text):
    """Prompt the user for a space-separated list and return a list."""
    items = input(prompt_text).strip().split()
    return items

def main():
    # General configuration
    domain = input("Enter domain name (e.g. ourcompany.com): ").strip()
    cluster = input("Enter cluster name (e.g. hscluster): ").strip()

    # Prompt for Anvil nodes and their IP addresses.
    anvil_nodes = prompt_list("Enter Anvil node names (space separated, e.g. anvil-1 anvil-2): ")
    anvil_ips = {}
    for node in anvil_nodes:
        ip = input(f"Enter IP address for Anvil node '{node}': ").strip()
        anvil_ips[node] = ip

    # Prompt for DSX nodes and their IP addresses.
    dsx_nodes = prompt_list("Enter DSX node names (space separated, e.g. dsx-1 dsx-2 dsx-3): ")
    dsx_ips = {}
    for node in dsx_nodes:
        ip = input(f"Enter IP address for DSX node '{node}': ").strip()
        dsx_ips[node] = ip

    # Create the prometheus.yaml configuration.
    output_file = "./prometheus/prometheus.yaml"
    with open(output_file, "w") as f:
        # Write the static configuration blocks.
        f.write("scrape_configs:\n")
        f.write("- job_name: prometheus\n")
        f.write("  static_configs:\n")
        f.write("  - labels:\n")
        f.write("      node_type: prometheus\n")
        f.write("    targets:\n")
        f.write("    - localhost:9090\n")
        f.write("### Add your hammerspace cluster\n")
        f.write("- job_name: cluster\n")
        f.write("  static_configs:\n")
        f.write("  - labels:\n")
        f.write(f"      cluster: {cluster}.{domain}\n")
        f.write(f"      instance: {cluster}.{domain}\n")
        f.write("      node_type: clusterip\n")
        f.write("    targets:\n")
        f.write("    - 10.0.0.71:9101\n")
        f.write("    - 10.0.0.71:9102\n")
        f.write("    - 10.0.0.71:9103\n")
        f.write("\n")
        
        # Write the Anvil nodes configuration.
        f.write("- job_name: anvil_nodes\n")
        f.write("  static_configs:\n")
        for node in anvil_nodes:
            ip = anvil_ips[node]
            f.write("  - labels:\n")
            f.write(f"      cluster: {cluster}.{domain}\n")
            f.write(f"      instance: {cluster}-{node}.{domain}\n")
            f.write("      node_type: anvil\n")
            f.write("    targets:\n")
            f.write(f"    - {ip}:9100\n")
        f.write("\n")
        
        # Write the DSX nodes configuration.
        f.write("- job_name: dsx_nodes\n")
        f.write("  static_configs:\n")
        for node in dsx_nodes:
            ip = dsx_ips[node]
            f.write("  - labels:\n")
            f.write(f"      cluster: {cluster}.{domain}\n")
            f.write(f"      instance: {cluster}-{node}.{domain}\n")
            f.write("      node_type: dsx\n")
            f.write("    targets:\n")
            f.write(f"    - {ip}:9100\n")
            f.write(f"    - {ip}:9105\n")
    
    print(f"{output_file} has been generated.")

if __name__ == "__main__":
    main()

