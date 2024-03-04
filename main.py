from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko
import mysql.connector
import re
from collections import defaultdict
from tqdm import tqdm

DB_HOST = "localhost"
DB_USER = ""
DB_PASSWORD = "!"
DB_DATABASE = ""
SSH_USERNAME = ""
SSH_PASSWORD = ""

router_issues = defaultdict(list)
ipv6_addresses = [
    "2001:4860:4860::8888", # Google DNS
    "2001:4860:4860::8844", # Google DNS
    "2606:4700:4700::1111", # Cloudflare
    "2a03:2880:f12c:183:face:b00c:0:25de", # Meta
    "2607:f8b0:4008:805::200e", # Google Main Site
    "2607:f8b0:4021::a", # Potentially Android updates
    "2606:2800:11f:2161:53c:2109:2296:185a", # Edgecast CDN
    "2607:f8b0:4008:813::2001", # Additional Google
    "2607:f8b0:4008:806::2001", # Additional Google
    "2606:2800:11f:5f1a:b359:a437:da60:e513" # Additional Edgecast
]

class DatabaseManager:
    def __init__(self, host, user, password, database):
        self.connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )

    def fetch_juniper_hostnames(self):
        cursor = self.connection.cursor()
#        cursor.execute("SELECT hostname FROM host_inventory WHERE vendor='Juniper' AND hostname NOT LIKE '%ex2300%' AND hostname NOT LIKE '%-mr0%' AND hostname NOT LIKE '%-ms0%' AND hostname NOT LIKE '%-ae0%' AND hostname NOT LIKE '%-fw0%' AND hostname NOT LIKE '%-wb0%' LIMIT 20")
# for ce specific checking. Will add with argparse when i'm not lazy
        cursor.execute("SELECT hostname FROM host_inventory WHERE vendor='Juniper' AND hostname LIKE '%-ce01'")
        hostnames = [item[0] for item in cursor.fetchall()]
        cursor.close()
        return hostnames

    def close(self):
        self.connection.close()

class RouterManager:
    def __init__(self, hostname):
        self.hostname = hostname
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self, username, password):
        self.ssh.connect(hostname=self.hostname, username=username, password=password, timeout=5)

    def disconnect(self):
        self.ssh.close()

    def execute_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        return stdout.read().decode()

    def analyze_interface(self, interface):
        ipv6_address_cmd = f"show configuration interfaces {interface} | display set"
        ipv6_metric_cmd = f"show configuration protocols isis interface {interface} | display set"
        ipv6_address_output = self.execute_command(ipv6_address_cmd)
        ipv6_metric_output = self.execute_command(ipv6_metric_cmd)

        ipv6_address = re.search(r"unit 0 family inet6 address ([\da-fA-F:]+)", ipv6_address_output)
        ipv6_metric = re.search(r"level 2 ipv6-unicast-metric (\d+)", ipv6_metric_output)

        return {
            'ipv6_address': ipv6_address.group(1) if ipv6_address else None,
            'ipv6_metric': int(ipv6_metric.group(1)) if ipv6_metric else None
        }

    def check_ipv6_unicast_topology(self):
        output = self.execute_command("show configuration protocols isis topologies")
        return "ipv6-unicast;" in output

    def get_ipv6_neighbor(self, interface):
        output = self.execute_command(f"show ipv6 neighbors interface {interface}")
        match = re.search(r"(\S+)\s+\S+\s+(stale|reachable|unreachable|delay)", output)
        return match.group(1) if match else None

    def ping_ipv6_address(self, ipv6_address):
        output = self.execute_command(f"ping {ipv6_address} count 2")
        match = re.search(r"(\d+) (packets )?received", output)
        if match:
            packets_received = int(match.group(1))
            return packets_received >= 1  # True if 1 or 2 packets were received
        else:
            print(output)
        return False

    def check_v6_tiedown(self):
        output = self.execute_command(f"show configuration routing-options rib inet6.0 static")
        return "discard" in output

    def check_v6_lo0(self):
        output = self.execute_command(f"show configuration interfaces lo0 unit 0 family inet6")
        return "address" in output

    def check_static_isis_export(self):
        output = self.execute_command("show configuration | display set | match Static-to-ISIS")
        required_configs = [
            "set policy-options policy-statement Static-to-ISIS term 1 from protocol static",
            "set policy-options policy-statement Static-to-ISIS term 1 then accept",
            "set protocols isis export Static-to-ISIS"
        ]
        route_filter_prefix = "set policy-options policy-statement Static-to-ISIS term 1 from route-filter"
        success = all(config in output for config in required_configs)
        route_filter_ipv6 = [line.split()[-3] for line in output.split('\n') if route_filter_prefix in line and "exact" in line]
        return {"success": success, "route_filter_ipv6": route_filter_ipv6}




    def get_interface_description(self, interface):
        interface = interface.replace('.0', '')
        description_cmd = f"show configuration interfaces {interface} description"
        description_output = self.execute_command(description_cmd)
        match = re.search(r'description "(.*)";', description_output)
        return match.group(1) if match else "No description"

    def check_inet6_route_table(self):
        command = "show route table inet6 exact ::/0"
        output = self.execute_command(command)
        issues = []  # List to hold any issues found
        active_routes_match = re.search(r"inet6.0: \d+ destinations, \d+ routes \((\d+) active", output)
        active_routes = int(active_routes_match.group(1)) if active_routes_match else 0
        default_route_exists = "::/0" in output
        if not default_route_exists:
            issues.append(f"Default IPv6 route (::/0) does not exist.")
        if active_routes < 900:
            issues.append(f"Only {active_routes} active IPv6 routes found, less than expected.")
        return issues

    def check_foptions_l34(self):
        output = self.execute_command(f"show configuration forwarding-options hash-key family inet")
        return {
            'layer-3': 'layer-3' in output,
            'layer-4': 'layer-4' in output
        }


    def check_pim_configuration(self, interface):
        pim_config_output = self.execute_command(f"show configuration protocols pim interface {interface}")
        issues = []
        if "mode sparse;" not in pim_config_output:
            issues.append("PIM mode sparse missing.")
        if "hello-interval 30;" not in pim_config_output:
            issues.append("PIM hello-interval 30 missing.")
        return issues

    def get_all_bfd_sessions(self):
        bfd_sessions_output = self.execute_command("show bfd session")
        bfd_sessions = {}
        for line in bfd_sessions_output.splitlines():
            match = re.search(r"(\S+)\s+(Up|Down)\s+(\S+)", line)
            if match:
                address, state, interface = match.groups()
                ip_version = '4' if '.' in address else '6'
                if interface not in bfd_sessions:
                    bfd_sessions[interface] = {'4': None, '6': None}
                bfd_sessions[interface][ip_version] = state
        return bfd_sessions

    def get_pim_neighbors(self):
        pim_neighbors_output = self.execute_command("show pim neighbors")
        pim_neighbors = {}
        for line in pim_neighbors_output.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            interface, ip_version = parts[0], parts[1]
            if interface not in pim_neighbors:
                pim_neighbors[interface] = {'4': False, '6': False}
            pim_neighbors[interface][ip_version] = True
        return pim_neighbors
#
## Building this out as a new class for now
# as I'd like to make it self-heal problems found.
# Due to ACX710 bug that kills UPS interfaces
# i'm manually spitting out what's needed to correct
class NetworkCorrectionManager:
    def __init__(self, analysis_results):
        self.analysis_results = analysis_results

    def generate_correction_commands(self):
        with open("network_correction_commands.txt", "w") as commands_file:
            for router in self.analysis_results:
                if router["has_issues"]:
                    hostname = router["hostname"]
                    combined_commands = "edit ;"

                    if "L3/L4 Missing in forwarding options." in router["issues"]:
                        combined_commands += " set forwarding-options hash-key family inet layer-3 ;"
                        combined_commands += " set forwarding-options hash-key family inet layer-4 ;"
                    if "Static-to-ISIS export policy incomplete." in router["issues"]:
                        combined_commands += " set policy-options policy-statement Static-to-ISIS term 1 from protocol static ;"
                        combined_commands += " set policy-options policy-statement Static-to-ISIS term 1 then accept ;"
                        combined_commands += " set protocols isis export Static-to-ISIS ;"

                    for interface, data in router.get("interfaces", {}).items():
                        for issue in data.get("issues", []):
                            if issue == "PIM mode sparse missing.":
                                command = f" set protocols pim interface {interface} mode sparse ;"
                                combined_commands += command
                            elif issue == "PIM hello-interval 30 missing.":
                                command = f" set protocols pim interface {interface} hello-interval 30 ;"
                                combined_commands += command


                    if combined_commands != "edit ;":
                        combined_commands += " commit and-quit"
                        commands_file.write(f'hi -c {hostname} "{combined_commands}"\n')

        print("Network correction commands generated and saved to network_correction_commands.txt")


def analyze_router(hostname):
    router_data = {
        "hostname": hostname,
        "interfaces": {},
        "issues": [],  # General issues not specific to an interface
        "successes": [],  # General successes not specific to an interface
        "has_issues": False
    }
    try:
        router = RouterManager(hostname)
        router.connect(SSH_USERNAME, SSH_PASSWORD)
##
## General Router Checks - Outside of interface loop
##
# Make sure the box has a full v6 table, and a default v6 route via igp
        route_table_issues = router.check_inet6_route_table()
        if route_table_issues:
            router_data["has_issues"] = True
            router_data["issues"].extend(route_table_issues)
        else:
            router_data["successes"].append("IPv6 route table checked with no issues found.")

# Make sure v6 unicast topology is set. Usually if missing, you won't have a full v6 table
        if not router.check_ipv6_unicast_topology():
            router_data["has_issues"] = True
            router_data["issues"].append("Missing IPv6 Unicast Topology.")
        else:
            router_data["successes"].append("IPv6 Unicast Topology is configured.")

# Check that a v6 tiedown (static discard) exists
        if not router.check_v6_tiedown():
            router_data["has_issues"] = True
            router_data["issues"].append("Missing a v6 tiedown.")
        else:
            router_data["successes"].append("IPv6 Static tiedown exists.")

# Check that a v6 address exists on lo0
        if not router.check_v6_lo0():
            router_data["has_issues"] = True
            router_data["issues"].append("IPv6 lo0 address is missing.")
        else:
            router_data["successes"].append("IPv6 lo0 address exists.")

# Check isis export policy to ensure all statements exist.....
        if (result := router.check_static_isis_export())["success"]:
            router_data["successes"].append(f"IPv6 PD Export Policy appears complete..  IPv6: {result['route_filter_ipv6']}")
        else:
            router_data["has_issues"] = True
            router_data["issues"].append("Static-to-ISIS export policy incomplete.")



# Check layer 3 / 4 hash key in forwarding options:
        l34_status = router.check_foptions_l34()
        if not l34_status["layer-3"] or not l34_status["layer-4"]:
            router_data["has_issues"] = True
            router_data["issues"].append("L3/L4 Missing in forwarding options.")
        else:
            router_data["successes"].append("L3/L4 hash-key forwarding options exist.")


# pull in the bfd session list once, to be used in the for interface loop
        bfd_sessions = router.get_all_bfd_sessions()

# pull in list of interfaces with isis neighbors.
        interfaces_output = router.execute_command("show isis adjacency")
        interfaces = re.findall(r"(\S+)\s+\S+\s+2\s+Up", interfaces_output)
# pull in pim neighbors once for interface loop
        pim_neighbors = router.get_pim_neighbors()

##
## Start for interface loop
##
        for interface in interfaces:
            description = router.get_interface_description(interface)
            router_data["interfaces"][interface] = {
                "description": description,
                "issues": [],
                "successes": []
            }

 # Analyze IPv6 configuration and metric
            ipv6_info = router.analyze_interface(interface)  # return {'ipv6_address': ..., 'ipv6_metric': ...}
            if ipv6_info['ipv6_address']:
                router_data["interfaces"][interface]["successes"].append(f"IPv6 address {ipv6_info['ipv6_address']} configured.")
            else:
                router_data["interfaces"][interface]["issues"].append("IPv6 address is missing.")
                router_data["has_issues"] = True
            if ipv6_info['ipv6_metric'] is not None:
                router_data["interfaces"][interface]["successes"].append(f"IPv6 ISIS metric {ipv6_info['ipv6_metric']} configured.")
            else:
                router_data["interfaces"][interface]["issues"].append("IPv6 ISIS metric is missing.")
                router_data["has_issues"] = True

# check v6 neighbors on isis interfaces, attempt to ping them.
            ipv6_neighbor = router.get_ipv6_neighbor(interface)
            if ipv6_neighbor:
                success = router.ping_ipv6_address(ipv6_neighbor)
                if success:
                    router_data["interfaces"][interface]["successes"].append(f"Successfully pinged IPv6 neighbor {ipv6_neighbor} on {interface}.")
                else:
                    router_data["interfaces"][interface]["issues"].append(f"Failed to ping IPv6 neighbor {ipv6_neighbor} on {interface}.")
                    router_data["has_issues"] = True
            else:
                router_data["interfaces"][interface]["issues"].append(f"No IPv6 neighbor found on {interface}.")
                router_data["has_issues"] = True

# basic per interface pim checks... hello-interval and pim mode sparse
            pim_issues = router.check_pim_configuration(interface)
            if pim_issues:
                router_data["interfaces"][interface]["issues"].extend(pim_issues)
                router_data["has_issues"] = True
            else:
                router_data["interfaces"][interface]["successes"].append(f"PIM configuration correct on {interface}.")
            interface_names = [match for match in interfaces]

# Checkin pim neighbor status
            ipv4_present = pim_neighbors.get(interface, {}).get('4', False)
            ipv6_present = pim_neighbors.get(interface, {}).get('6', False)
            if ipv4_present and ipv6_present:
                router_data["interfaces"][interface]["successes"].append("Both IPv4 and IPv6 PIM neighbors present.")
            else:
                missing_versions = []
                if not ipv4_present:
                    missing_versions.append("IPv4")
                if not ipv6_present:
                    missing_versions.append("IPv6")
                router_data["interfaces"][interface]["issues"].append(f"Missing PIM neighbors for: {', '.join(missing_versions)}.")
                router_data["has_issues"] = True

# check status of bfd
            ipv4_state = bfd_sessions.get(interface, {}).get('4')
            ipv6_state = bfd_sessions.get(interface, {}).get('6')
            if ipv4_state == "Up":
                router_data["interfaces"][interface]["successes"].append(f"BFD IPv4 session is Up for {interface}.")
            else:
                router_data["interfaces"][interface]["issues"].append(f"Missing or down BFD IPv4 session for {interface}.")
                router_data["has_issues"] = True
            if ipv6_state == "Up":
                router_data["interfaces"][interface]["successes"].append(f"BFD IPv6 session is Up for {interface}.")
            else:
                router_data["interfaces"][interface]["issues"].append(f"Missing or down BFD IPv6 session for {interface}.")
                router_data["has_issues"] = True
        router.disconnect()
    except Exception as e:
        router_data["has_issues"] = True
        print(e)
        router_data["issues"].append(f"Error analyzing {hostname}: {e}")
    return router_data


def generate_html_report(analysis_results):
# Sort routers based on whether they have issues or not
    sorted_results = sorted(analysis_results, key=lambda x: not x["has_issues"])

    html_content = """<!DOCTYPE html><html><head><style> body { font-family: Arial, sans-serif; margin: 0; padding: 20px; box-sizing: border-box; } h2 { color: #333; } table { width:
    100%; border-collapse: collapse; margin-top: 20px; } th, td { padding: 10px; border: 1px solid #ccc; text-align: left; } th { background-color: #007bff; color: white; } .no-issue { background-color:
    #28a745; color: white; } .has-issue { background-color: #dc3545; color: white; } .success { color: #28a745; } .error { color: #dc3545; } .interface-name { font-weight: bold; }
    </style></head><body>"""

    for router in sorted_results:
        table_header_class = "no-issue" if not router["has_issues"] else "has-issue"
        html_content += f"<table><tr><th colspan='2' class='{table_header_class}'>{router['hostname']}</th></tr>"

# Display general router issues and successes
        for issue in router.get("issues", []):
            html_content += f"<tr><td colspan='2' class='error'>&#x2717; {issue}</td></tr>"
        for success in router.get("successes", []):
            html_content += f"<tr><td colspan='2' class='success'>&#x2713; {success}</td></tr>"

# Display interface-specific issues and successes
        for interface, data in router["interfaces"].items():
            description = data.get("description", "No description available")
            html_content += f"<tr><td colspan='2' class='interface-name'>{interface} | [ {description} ]</td></tr>"
            for issue in data.get("issues", []):
                html_content += f"<tr><td class='error'>&#x2717; {issue}</td></tr>"
            for success in data.get("successes", []):
                html_content += f"<tr><td class='success'>&#x2713; {success}</td></tr>"
        html_content += "</table><br>"
    html_content += "</body></html>"
    file_path = "/var/www/html/scripts/network_report.html"
    with open(file_path, "w") as file:
        file.write(html_content)
    print(f"Report generated: {file_path}")

def main():
    db_manager = DatabaseManager(DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE)
    hostnames = db_manager.fetch_juniper_hostnames()
    db_manager.close()
    progress = tqdm(total=len(hostnames), desc="Starting...")
    analysis_results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_hostname = {executor.submit(analyze_router, hostname): hostname for hostname in hostnames}
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            progress.set_description(f"Processing {hostname}")
            try:
                result = future.result()
                analysis_results.append(result)
                # progress.set_description("Starting...")
            except Exception as e:
                tqdm.write(f"Analysis failed for {hostname}: {e}")
            finally:
                progress.update(1)
    progress.close()
    generate_html_report(analysis_results)
    correction_manager = NetworkCorrectionManager(analysis_results)
    correction_manager.generate_correction_commands()


if __name__ == "__main__":
    main()
