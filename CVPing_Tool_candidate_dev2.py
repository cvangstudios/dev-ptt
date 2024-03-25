import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import subprocess
import csv
import threading
import time
import socket
import configparser

# Dictionary to store ping processes and results
ping_processes = {}

# Dictionary to store previous host status
previous_host_status = {}

# Variables to store the current sort column and method
current_sort_column = ""
current_sort_method = ""

def load_config():
    config = configparser.ConfigParser()
    if config.read("ping.ini"):
        if "Settings" in config:
            if "domain_name" in config["Settings"]:
                domain_entry.delete(0, tk.END)
                domain_entry.insert(0, config["Settings"]["domain_name"])
            if "delay" in config["Settings"]:
                delay_entry.delete(0, tk.END)
                delay_entry.insert(0, config["Settings"]["delay"])

def load_hosts():
    file_path = filedialog.askopenfilename(title="Select Host File", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            lines = file.readlines()
            if lines:
                test_description = lines[0].strip()
                root.title(f"Cher's Ping Test Tool                   {test_description}")
                hosts = [line.strip() for line in lines[1:]]
                domain = domain_entry.get().strip()
                for host in hosts:
                    if '.' not in host:
                        host = f"{host}.{domain}"
                    if host not in host_entries:
                        add_host_entry(host)

def start_ping():
    start_button.config(state=tk.DISABLED)
    new_test_button.config(state=tk.DISABLED)
    export_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    for host_entry in host_entries.values():
        host = host_entry["host"]
        ip_address = host_entry["ip_address"]
        delay = int(delay_entry.get())  # Get the delay in seconds
        if host not in ping_processes:
            ping_processes[host] = {
                "process": None,
                "sent": 0,
                "received": 0,
                "consecutive_missed": 0,
                "consecutive_replies": 0,
                "stop_event": threading.Event()
            }
        if not ping_processes[host]["process"] or ping_processes[host]["process"].poll() is not None:
            if ping_processes[host]["stop_event"].is_set():
                ping_processes[host]["stop_event"].clear()
            start_ping_process(host, ip_address, delay)

def start_ping_process(host, ip_address, delay):
    def ping_loop():
        ping_command = ["ping", "-t", ip_address]  # Use "-t" for continuous pinging
        process = subprocess.Popen(
            ping_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        ping_processes[host]["process"] = process
        if ping_processes[host]["received"] == 0:
            update_host_entry(host, "Host Unreachable", "red")
        sent = ping_processes[host]["sent"]
        received = ping_processes[host]["received"]
        update_host_entry(host)

        while not ping_processes[host]["stop_event"].is_set():
            output = process.stdout.readline()
            if output:
                if host in ping_processes:
                    ping_processes[host]["sent"] += 1
                    if "Reply from" in output:
                        reply_ip = output.split()[2].strip(":")
                        if reply_ip == ip_address:
                            ping_processes[host]["received"] += 1
                            ping_processes[host]["consecutive_replies"] += 1
                            ping_processes[host]["consecutive_missed"] = 0
                        else:
                            ping_processes[host]["consecutive_missed"] += 1
                            ping_processes[host]["consecutive_replies"] = 0
                    elif "Destination host unreachable" in output or "Request timed out" in output:
                        ping_processes[host]["consecutive_missed"] += 1
                        ping_processes[host]["consecutive_replies"] = 0
                    update_host_entry(host)
            time.sleep(delay)

        process.terminate()
        process.wait()

    ping_thread = threading.Thread(target=ping_loop)
    ping_thread.start()

def update_host_entry(host, status=None, status_color=None):
    global previous_host_status, current_sort_column, current_sort_method
    sent = ping_processes[host]["sent"]
    received = ping_processes[host]["received"]
    lost = sent - received
    consecutive_missed = ping_processes[host]["consecutive_missed"]
    consecutive_replies = ping_processes[host]["consecutive_replies"]

    if sent > 0:
        loss_percentage = (lost / sent) * 100
    else:
        loss_percentage = 0

    if status is None:
        if consecutive_replies >= 5:
            status = "Host Alive"
            status_color = "green"
        elif consecutive_missed >= 5:
            status = "Host Unreachable"
            status_color = "red"
        else:
            status = "Checking..."
            status_color = "orange"

    values = (host_entries[host]["host"], host_entries[host]["ip_address"], status, str(sent), str(received), f"{lost} ({loss_percentage:.2f}%)")
    results_treeview.item(host_entries[host]["item"], values=values, tags=(status_color,))

    # Check if the host status has changed
    if host in previous_host_status and previous_host_status[host] != status:
        # Sort the results based on the "Host Status" column if it's the current sort column
        if current_sort_column == "Host Status":
            sort_column("Host Status", current_sort_method)

    # Update the previous host status
    previous_host_status[host] = status

def stop_ping():
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    new_test_button.config(state=tk.NORMAL)
    export_button.config(state=tk.NORMAL)
    for host in ping_processes:
        ping_processes[host]["stop_event"].set()

def new_test():
    if any(ping_processes.values()):
        response = messagebox.askyesnocancel("Save Test Results", "Do you want to save the test results before starting a new test?")
        if response is None:
            return
        elif response:
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", title="Save Test Results")
            if file_path:
                export_results(file_path)
            else:
                return
    stop_ping()
    ping_processes.clear()
    previous_host_status.clear()
    results_treeview.delete(*results_treeview.get_children())
    host_entries.clear()
    new_test_button.config(state=tk.DISABLED)
    export_button.config(state=tk.DISABLED)
    root.title("Cher's Ping Test Tool")  # Reset the application title

def edit_delay():
    new_delay = simpledialog.askinteger("Edit Delay", "Enter the new delay in seconds:", initialvalue=int(delay_entry.get()))
    if new_delay is not None:
        delay_entry.delete(0, tk.END)
        delay_entry.insert(0, str(new_delay))

def export_results(file_path):
    with open(file_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Host", "Host IP", "Host Status", "Ping Results", "Lost"])
        for host_entry in host_entries.values():
            values = results_treeview.item(host_entry["item"])["values"]
            writer.writerow(values)

def copy_results():
    formatted_results = "Host\tHost IP\tHost Status\tPing Results\tLost\n"
    for host_entry in host_entries.values():
        values = results_treeview.item(host_entry["item"])["values"]
        formatted_results += "\t".join(values) + "\n"
    root.clipboard_clear()
    root.clipboard_append(formatted_results)
    messagebox.showinfo("Copy Results", "Results copied to clipboard!")

def add_host_entry(host):
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        ip_address = host

    item = results_treeview.insert("", "end", values=(host, ip_address, "Host Unreachable", "0", "0", "0 (0%)"))
    host_entries[host] = {
        "host": host,
        "ip_address": ip_address,
        "item": item
    }

def sort_column(column, method):
    global current_sort_column, current_sort_method
    current_sort_column = column
    current_sort_method = method

    # Reset the sort method for other columns
    for col in ["Host", "Host IP", "Host Status"]:
        if col != column:
            col_heading = results_treeview.heading(col)
            col_heading.configure(text=f"{col}\n▼ None")

    # Update the column heading text to reflect the selected sort method
    col_heading = results_treeview.heading(column)
    col_heading.configure(text=f"{column}\n{'▲' if method == 'ascending' else '▼'} {method.capitalize()}")

    reverse = method == "descending"
    items = [(results_treeview.set(k, column), k) for k in results_treeview.get_children("")]
    items.sort(reverse=reverse)
    for index, (_, k) in enumerate(items):
        results_treeview.move(k, "", index)

def sort_column_dropdown(column, method):
    sort_column(column, method)

root = tk.Tk()
root.title("Cher's Ping Test Tool")
root.geometry("800x600")  # Set initial window size
root.minsize(600, 400)  # Set minimum window size

# Create a style for the Treeview
style = ttk.Style()
style.configure("Treeview", borderwidth=1, relief="solid")
style.configure("Treeview.Heading", borderwidth=1, relief="solid")
style.layout("Treeview", [
    ("Treeview.treearea", {"sticky": "nswe"})
])
style.map("Treeview", relief=[("selected", "solid")])

# Create a frame for the buttons
buttons_frame = tk.Frame(root)
buttons_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

# Create the buttons
load_hosts_button = tk.Button(buttons_frame, text="Load Hosts", command=load_hosts)
load_hosts_button.pack(pady=5)

start_button = tk.Button(buttons_frame, text="Start", command=start_ping)
start_button.pack(pady=5)

stop_button = tk.Button(buttons_frame, text="Stop", state=tk.DISABLED, command=stop_ping)
stop_button.pack(pady=5)

new_test_button = tk.Button(buttons_frame, text="New Test", state=tk.DISABLED, command=new_test)
new_test_button.pack(pady=5)

edit_delay_button = tk.Button(buttons_frame, text="Edit Delay", command=edit_delay)
edit_delay_button.pack(pady=5)

export_button = tk.Button(buttons_frame, text="Export Results", state=tk.DISABLED, command=lambda: export_results(filedialog.asksaveasfilename(defaultextension=".csv", title="Export Results")))
export_button.pack(pady=5)

copy_button = tk.Button(buttons_frame, text="Copy Results", command=copy_results)
copy_button.pack(pady=5)

exit_button = tk.Button(buttons_frame, text="Exit", command=root.quit)
exit_button.pack(pady=5)

delay_label = tk.Label(buttons_frame, text="Delay (seconds):")
delay_label.pack(pady=5)

delay_entry = tk.Entry(buttons_frame, width=5)
delay_entry.insert(0, "1")  # Default delay of 1 second
delay_entry.pack(pady=5)

domain_label = tk.Label(buttons_frame, text="Domain Name:")
domain_label.pack(pady=5)

domain_entry = tk.Entry(buttons_frame, width=20)
domain_entry.pack(pady=5)

# Create a frame for the host entries and results
main_frame = tk.Frame(root)
main_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

# Create a Treeview widget for the results
results_treeview = ttk.Treeview(main_frame, columns=("Host", "Host IP", "Host Status", "Sent", "Received", "Lost"), show="headings")
results_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Configure column headings
host_heading = results_treeview.heading("Host", text="Host\n▼ None")
host_ip_heading = results_treeview.heading("Host IP", text="Host IP\n▼ None")
host_status_heading = results_treeview.heading("Host Status", text="Host Status\n▼ None")
results_treeview.heading("Sent", text="Sent")
results_treeview.heading("Received", text="Received")
results_treeview.heading("Lost", text="Lost")

# Create dropdown menus for sorting columns
sort_options = ["None", "Ascending", "Descending"]

host_dropdown = ttk.OptionMenu(host_heading, tk.StringVar(), *sort_options, command=lambda method: sort_column_dropdown("Host", method.lower()))
host_dropdown.configure(width=10)
host_heading.configure(anchor=tk.W, command=None)  # Remove the existing command
host_heading._w.pack_forget()  # Hide the existing heading label
host_heading._w = host_dropdown  # Replace the heading label with the dropdown menu
host_heading._w.pack(side=tk.LEFT)

host_ip_dropdown = ttk.OptionMenu(host_ip_heading, tk.StringVar(), *sort_options, command=lambda method: sort_column_dropdown("Host IP", method.lower()))
host_ip_dropdown.configure(width=10)
host_ip_heading.configure(anchor=tk.W, command=None)
host_ip_heading._w.pack_forget()
host_ip_heading._w = host_ip_dropdown
host_ip_heading._w.pack(side=tk.LEFT)

host_status_dropdown = ttk.OptionMenu(host_status_heading, tk.StringVar(), *sort_options, command=lambda method: sort_column_dropdown("Host Status", method.lower()))
host_status_dropdown.configure(width=10)
host_status_heading.configure(anchor=tk.W, command=None)
host_status_heading._w.pack_forget()
host_status_heading._w = host_status_dropdown
host_status_heading._w.pack(side=tk.LEFT)

############# WHERE IT STOPPED



# Configure column widths
results_treeview.column("Host", width=200, minwidth=100, stretch=True)
results_treeview.column("Host IP", width=150, minwidth=100, stretch=True)
results_treeview.column("Host Status", width=150, minwidth=100, stretch=True)
results_treeview.column("Sent", width=100, minwidth=50, stretch=True)
results_treeview.column("Received", width=100, minwidth=50, stretch=True)
results_treeview.column("Lost", width=150, minwidth=100, stretch=True)

# Configure row colors based on host status
results_treeview.tag_configure("red", background="#FFCCCB")
results_treeview.tag_configure("orange", background="#FFE5B4")
results_treeview.tag_configure("green", background="#C1FFC1")

# Create a scrollbar for the results
results_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=results_treeview.yview)
results_scrollbar.pack(side=tk.LEFT, fill=tk.Y)

# Configure the Treeview to use the scrollbar
results_treeview.configure(yscrollcommand=results_scrollbar.set)

# Dictionary to store host entries
host_entries = {}

# Dictionary to store sort order for each column
sort_order = {
    "Host": "ascending",
    "Host IP": "ascending",
    "Host Status": "ascending"
}

# Load configuration from ping.ini
load_config()

# Start the main event loop
root.mainloop()