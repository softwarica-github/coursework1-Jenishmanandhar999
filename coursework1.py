import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from threading import Thread
import queue
import re  # For IP address validation

# Validate IP address
def validate_ip(ip):
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip)

# Updated Port Scanner Logic to include closed ports
def scan_port(ip, port, result_queue):
    try:
        scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        status = scanner.connect_ex((ip, port))
        if not status:
            result_queue.put(f"Port {port}: Open\n")
        else:
            result_queue.put(f"Port {port}: Closed\n")  # Indicate closed ports
        scanner.close()
    except Exception as e:
        result_queue.put(f"Port {port}: Error - {e}\n")

# Start the scan with validation
def start_scan(ip, range_start, range_end, display, scan_btn, progress_bar):
    if not validate_ip(ip):
        messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
        scan_btn.config(state=tk.NORMAL)
        return

    def thread_target():
        result_queue = queue.Queue()
        threads = []
        total_ports = range_end - range_start + 1
        ports_scanned = 0

        for port in range(range_start, range_end + 1):
            thread = Thread(target=scan_port, args=(ip, port, result_queue))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
            ports_scanned += 1
            progress = (ports_scanned / total_ports) * 100
            progress_bar['value'] = progress
            root.update_idletasks()

        while not result_queue.empty():
            display.insert(tk.END, result_queue.get())

        scan_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Scan Complete", "Port scanning has completed.")
        progress_bar['value'] = 0

    Thread(target=thread_target).start()

# Enhanced GUI with progress bar and improved layout
def gui():
    global root  # Make root a global variable for progress bar updates
    root = tk.Tk()
    root.title("Port Scanner")
    root.geometry("500x450")  # Adjusted for additional elements
    root.configure(bg="#333")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", foreground="#333", background="#ccc")
    style.configure("TProgressbar", thickness=20)

    ttk.Label(root, text="Target IP:", background="#333", foreground="#fff").pack(pady=(10, 0))
    ip_entry = ttk.Entry(root)
    ip_entry.pack(pady=5, fill=tk.X, padx=10)

    ttk.Label(root, text="Start Port:", background="#333", foreground="#fff").pack(pady=5)
    start_port_entry = ttk.Entry(root)
    start_port_entry.pack(pady=5, fill=tk.X, padx=10)

    ttk.Label(root, text="End Port:", background="#333", foreground="#fff").pack(pady=5)
    end_port_entry = ttk.Entry(root)
    end_port_entry.pack(pady=5, fill=tk.X, padx=10)

    scan_btn = ttk.Button(root, text="Start Scan", command=lambda: [
        scan_btn.config(state=tk.DISABLED),
        start_scan(ip_entry.get(), int(start_port_entry.get()), int(end_port_entry.get()), result_display, scan_btn, progress_bar)])
    scan_btn.pack(pady=(5, 10))

    progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=100, mode='determinate')
    progress_bar.pack(pady=(0, 10), fill=tk.X, padx=10)

    result_display = scrolledtext.ScrolledText(root, height=12)
    result_display.pack(pady=5, fill=tk.BOTH, expand=True, padx=10)

    root.mainloop()

if __name__ == "__main__":
    gui()
