import requests
import socket
import subprocess
import ipaddress
import platform

# Function to prompt user for IP address
def get_user_ip():
    return input("Enter the IP address you want to investigate: ")

# Function to check if IP is private
def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

# Function to get public IP of the network (for private IPs)
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        public_ip = response.json()['ip']
        return public_ip
    except Exception as e:
        return f"Failed to retrieve public IP: {str(e)}"

# Function to perform reverse DNS lookup (works for private and public IPs)
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Function to ping the IP to check reachability
def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ['ping', param, '1', ip]
    try:
        output = subprocess.run(command, capture_output=True, text=True)
        if output.returncode == 0:
            return f"{ip} is reachable"
        else:
            return f"{ip} is not reachable"
    except Exception as e:
        return f"Ping failed: {str(e)}"

# Function to retrieve ARP info to get the MAC address (for private IPs on the same local network)
def get_mac_address(ip):
    try:
        if platform.system().lower() == "windows":
            command = ['arp', '-a', ip]
        else:
            command = ['arp', ip]

        output = subprocess.run(command, capture_output=True, text=True)
        return output.stdout
    except Exception as e:
        return f"Failed to retrieve MAC address: {str(e)}"

# Function to get geo-location info from ip-api.com (No API key required for public IPs)
def get_geo_location(ip):
    response = requests.get(f'http://ip-api.com/json/{ip}')
    if response.status_code != 200:
        print(f"Error: Unable to retrieve geo-location info. Status code: {response.status_code}")
        return None
    try:
        return response.json()
    except json.decoder.JSONDecodeError:
        print("Error: Received invalid JSON data from ip-api.com.")
        return None

# Function to attempt to gather device information using NetBIOS (only on Windows)
def get_device_info(ip):
    try:
        if platform.system().lower() == "windows":
            output = subprocess.run(['nbtstat', '-A', ip], capture_output=True, text=True)
            return output.stdout
        else:
            return "NetBIOS info retrieval only supported on Windows."
    except Exception as e:
        return f"Failed to retrieve device info: {str(e)}"

# Function to perform WHOIS lookup for IP
def whois_lookup(ip):
    try:
        command = ['whois', ip]
        output = subprocess.run(command, capture_output=True, text=True)
        return output.stdout.decode('utf-8')
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

# Main script logic
if __name__ == "__main__":
    # Ask the user for an IP address
    target_ip = get_user_ip()

    if is_private_ip(target_ip):
        print("Private IP detected. Gathering as much local information as possible...")

        # Ping the IP to check if it's reachable
        ping_result = ping_ip(target_ip)
        print(f"Ping Result: {ping_result}")

        # Reverse DNS Lookup
        reverse_hostname = reverse_dns(target_ip)
        if reverse_hostname:
            print(f"Reverse DNS: {reverse_hostname}")
        else:
            print("No reverse DNS available.")

        # MAC Address (ARP lookup)
        mac_address = get_mac_address(target_ip)
        print(f"MAC Address Information: {mac_address}")

        # Device Information (NetBIOS or local tools on Windows)
        device_info = get_device_info(target_ip)
        print(f"Device Info: {device_info}")

        # Get public IP and treat it as a public IP for OSINT
        public_ip = get_public_ip()
        if public_ip:
            print(f"\nPublic IP of the network: {public_ip}")
            print("\nGathering information about the public IP...")

            # Public IP lookup (geo-location)
            geo_info = get_geo_location(public_ip)
            if geo_info:
                print("\n### Geo-Location Information ###")
                print(f"City: {geo_info.get('city', 'N/A')}")
                print(f"Region: {geo_info.get('regionName', 'N/A')}")
                print(f"Country: {geo_info.get('country', 'N/A')}")
                print(f"Latitude: {geo_info.get('lat', 'N/A')}")
                print(f"Longitude: {geo_info.get('lon', 'N/A')}")
                print(f"ISP: {geo_info.get('isp', 'N/A')}")
                print(f"Timezone: {geo_info.get('timezone', 'N/A')}")
            else:
                print("No geo-location info available.")

            # Reverse DNS Lookup for public IP
            reverse_hostname = reverse_dns(public_ip)
            if reverse_hostname:
                print(f"\n### Reverse DNS ###\nReverse Hostname: {reverse_hostname}")
            else:
                print("Reverse DNS: N/A")

            # WHOIS Lookup for public IP
            whois_info = whois_lookup(public_ip)
            print(f"\n### WHOIS Information ###\n{whois_info}")
        
    else:
        print("Public IP detected. Gathering public information...")

        # Public IP lookup (geo-location)
        geo_info = get_geo_location(target_ip)
        if geo_info:
            print("\n### Geo-Location Information ###")
            print(f"City: {geo_info.get('city', 'N/A')}")
            print(f"Region: {geo_info.get('regionName', 'N/A')}")
            print(f"Country: {geo_info.get('country', 'N/A')}")
            print(f"Latitude: {geo_info.get('lat', 'N/A')}")
            print(f"Longitude: {geo_info.get('lon', 'N/A')}")
            print(f"ISP: {geo_info.get('isp', 'N/A')}")
            print(f"Timezone: {geo_info.get('timezone', 'N/A')}")
        else:
            print("No geo-location info available.")

        # Reverse DNS Lookup
        reverse_hostname = reverse_dns(target_ip)
        if reverse_hostname:
            print(f"\n### Reverse DNS ###\nReverse Hostname: {reverse_hostname}")
        else:
            print("Reverse DNS: N/A")

        # WHOIS Lookup
        whois_info = whois_lookup(target_ip)
        print(f"\n### WHOIS Information ###\n{whois_info}")
