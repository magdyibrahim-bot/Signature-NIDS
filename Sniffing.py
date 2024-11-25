#Allows the program to run multiple threads concurrently. 
#This is useful for running tasks like packet sniffing in 
#the background while keeping the GUI responsive.
import threading

#Provides regular expression support for pattern matching
#(used in signature detection).
import re

#SCAPY to use it in Sniffing and Analysis Packets.
from scapy.all import sniff, wrpcap,IP, TCP, UDP,ICMP

#Used to record timestamps for packets or logs.
from datetime import datetime

#Handles logging of detected alerts or other 
#system events to a file.
import logging

#Provides a graphical user interface (GUI)
#toolkit for displaying alerts and other visualizations.
import tkinter as tk
from tkinter import ttk

#Used for creating real-time charts of network traffic.
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

###########################################################

# Configuration
DDOS_THRESHOLD = 1000  # Max packets from a single IP
SIGNATURES = [
    {"name": "SQL Injection", "pattern": r"(SELECT .* FROM|UNION SELECT|OR '1'='1')"},
    {"name": "XSS Attack", "pattern": r"(<script>.*<\/script>)"},
    {"name": "HTTP Flood", "pattern": r"(GET \/ HTTP\/1\.1|POST \/ HTTP\/1\.1)"},
]

# Global Variables
traffic_stats = {"TCP": 0, "UDP": 0, "ICMP": 0}
alert_logs = []
ddos_sources = {}

# Logging Configuration
logging.basicConfig(level=logging.INFO, filename="nids.log", filemode="a", 
                    format="%(asctime)s - %(levelname)s - %(message)s")

# GUI Setup
root = tk.Tk()
root.title("Signature-based NIDS")

# GUI Elements
alert_box = tk.Text(root, height=10, width=100, bg="black", fg="lime")
alert_box.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Protocol Traffic Chart
fig = Figure(figsize=(6, 4), dpi=100)
traffic_chart = fig.add_subplot(111)
canvas = FigureCanvasTkAgg(fig, root)
canvas.get_tk_widget().grid(row=1, column=0, columnspan=2)

# Functions
""" 
This function handles:

    Storing alerts: Adds the alert to a list (alert_logs).
    Displaying alerts in the GUI: Shows the alert in the 
    GUI’s alert box.
    Logging alerts to a file: Writes the alert to the nids.
    log file for record-keeping.
"""
def log_alert(alert):
    """Log alerts to file and display in the GUI."""
    alert_logs.append(alert)
    alert_box.insert(tk.END, alert + "\n")
    alert_box.see(tk.END)
    logging.warning(alert)

def match_signatures(payload):
    """Match payloads against attack signatures."""
    for sig in SIGNATURES:
        if re.search(sig["pattern"], payload, re.IGNORECASE):
            return sig["name"]
    return None

def process_packet(packet):
    """Analyze each packet for malicious patterns and update stats."""
    """ 
        ddos_sources is a dictionary (key-value pair structure) where:
            The key is the source_ip (IP address of the sender).
            The value is the count of packets received from that source_ip.
    """
    global traffic_stats, ddos_sources   # [{"192.168.1.1":100} , {.2:200}]
    """ If the condition is True, it means:
            The packet includes the IP layer.
            It is valid for further processing (e.g., analyzing source/destination IPs, protocol types, etc.).
            If the condition is False, it means:
        The packet does not include the IP layer.
            It could be:
            A lower-layer protocol (like ARP).
            An incomplete or malformed packet. 
    """
    if IP in packet:
        """ 
            Identifies the protocol used by the packet:
            TCP (Transmission Control Protocol): Common for web traffic (HTTP, HTTPS).
            UDP (User Datagram Protocol): Used in DNS, video streaming, etc.
            ICMP (Internet Control Message Protocol): Used for error messages and tools like ping.
        """
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP"
        """ Increments the count of packets for the identified protocol in the traffic_stats dictionary.
            This is used to generate real-time traffic visualizations. 
        """
        traffic_stats[proto] += 1
       
        source_ip = packet[IP].src              #Extract the Source IP Address from Packet.
        """ Payload is the Data Portion
            Converts the payload to a string for further analysis.
        """
        if TCP in packet:
            payload = str(packet[TCP].payload)
        elif UDP in packet:
            payload = str(packet[UDP].payload)
        else:
            payload = str(packet[ICMP].payload)
        
        # DDoS Detection
        """
            Checks if the source_ip exists in the ddos_sources dictionary:
            If it exists: Returns the current count of packets for that IP.
            If it does not exist: Returns 0 as the default value (the second argument to .get()).
        """
        ddos_sources[source_ip] = ddos_sources.get(source_ip, 0) + 1
        """
            Once the count of packets from a specific IP exceeds the pre-defined DDoS_THRESHOLD (e.g., 50 packets), it raises an alert. 
        """
        if ddos_sources[source_ip] > DDOS_THRESHOLD:
            alert = f"DDoS Alert: {source_ip} exceeds {DDOS_THRESHOLD} packets!"
            log_alert(alert)
        
        # Signature Matching
        match = match_signatures(payload)
        if match:
            alert = f"Signature Match: {match} detected from {source_ip}."
            log_alert(alert)
            
       
        # Update Traffic Visualization
        update_traffic_chart()

def update_traffic_chart():
    #Update the traffic chart with current protocol statistics.
    traffic_chart.clear()
    traffic_chart.bar(traffic_stats.keys(), traffic_stats.values(), color=["blue", "green", "red"])
    traffic_chart.set_title("Traffic by Protocol")
    traffic_chart.set_xlabel("Protocol")
    traffic_chart.set_ylabel("Packet Count")
    canvas.draw()

def start_sniffing():
    """Start packet sniffing in a separate thread."""
    sniff_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=0))
     #wrpcap("output_file.pcap", sniff_thread)
    sniff_thread.daemon = True  # Allows program exit even if thread is running
    sniff_thread.start()

# Start NIDS
start_sniffing()   #Invokes the function, which starts the background packet sniffing process.
""" 
Starts the Tkinter GUI's main event loop, which:
Keeps the GUI running and responsive.
Handles user interactions, such as 
displaying alerts or visualizing traffic.
"""
root.mainloop()    