import os
import tkinter as tk
import socket
import threading
import uuid
import re
import platform
import psutil
from tkinter import messagebox
from datetime import datetime
import pickle
import tkinter.ttk as ttk
import cpuinfo
import GPUtil
import json

global client_socket
server_port = 5001


# FUNCTIONS OF GETTING PC INFO:`

def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor


def get_sys_info():
    """
    This function gets the system information
    :return: a string with system info divided by \n
    """
    uname = platform.uname()
    reply = " System @"
    reply += f"System: {uname.system}\n"
    reply += f"Node Name: {uname.node}\n"
    reply += f"Release: {uname.release}\n"
    reply += f"Version: {uname.version}\n"
    reply += f"Machine: {uname.machine}\n"
    reply += f"Processor: {uname.processor}\n"
    reply += f"Processor: {cpuinfo.get_cpu_info()['brand_raw']}\n"
    reply += f"Ip-Address: {socket.gethostbyname(socket.gethostname())}\n"
    reply += f"Mac-Address: {':'.join(re.findall('..', '%012x' % uuid.getnode()))}\n"
    return reply


def get_boot_time_info():
    """
    This function gets the PC boot time
    boot time is the time that the PC was turn on
    :return: PC boot time
    """
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)

    reply = " Boot Time @"
    reply += f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"
    return reply


def get_cpu_info():
    """
    This function gets the CPU information
    :return: a string with CPU information divided by \n
    """

    reply = " CPU @"
    # number of cores
    reply += f"Physical cores: {psutil.cpu_count(logical=False)}\n"
    reply += f"Total cores: {psutil.cpu_count(logical=True)}\n"
    # CPU frequencies
    cpufreq = psutil.cpu_freq()
    reply += f"Max Frequency: {cpufreq.max:.2f}Mhz\n"
    reply += f"Min Frequency: {cpufreq.min:.2f}Mhz\n"
    reply += f"Current Frequency: {cpufreq.current:.2f}Mhz\n"
    # CPU usage
    reply += "CPU Usage Per Core:\n"
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        reply += f"Core {i}: {percentage}%\n"
    reply += f"Total CPU Usage: {psutil.cpu_percent()}%\n"
    return reply


def get_memory_info():
    """
    This function gets the memory information
    :return: a string with memory information divided by \n
    """

    reply = " Memory @"
    # get the memory details
    svmem = psutil.virtual_memory()
    reply += f"Total: {get_size(svmem.total)}\n"
    reply += f"Available: {get_size(svmem.available)}\n"
    reply += f"Used: {get_size(svmem.used)}\n"
    reply += f"Percentage: {svmem.percent}%\n"
    return reply


def get_swap_memory_info():
    """
    This function gets the swap memory information
    swap memory is the overflow of memory that doesn't
     fit the RAM storage limit,
     which is placed on the hard drive.
    :return: a string with swap memory information divided by \n
    """

    reply = " SWAP @"
    # get the swap memory details(if exists)
    swap = psutil.swap_memory()
    reply += f"Total: {get_size(swap.total)}\n"
    reply += f"Free: {get_size(swap.free)}\n"
    reply += f"Used: {get_size(swap.used)}\n"
    reply += f"Percentage: {swap.percent}%\n"
    return reply


def get_disk_info():
    """
    This function gets the disk information
    :return: a string with disk information divided by \n
    """

    reply = "Disk @"
    reply += "Partitions and Usage:\n"
    # get all disk partitions
    partitions = psutil.disk_partitions()
    for partition in partitions:
        reply += f"=== Device: {partition.device} ===\n"
        reply += f"  Mountpoint: {partition.mountpoint}\n"
        reply += f"  File system type: {partition.fstype}\n"
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            # this can be catched due to the disk that
            # isn't ready
            continue
        reply += f"  Total Size: {get_size(partition_usage.total)}\n"
        reply += f"  Used: {get_size(partition_usage.used)}\n"
        reply += f"  Free: {get_size(partition_usage.free)}\n"
        reply += f"  Percentage: {partition_usage.percent}%\n"
    # get IO statistics since boot
    disk_io = psutil.disk_io_counters()
    reply += f"Total read: {get_size(disk_io.read_bytes)}\n"
    reply += f"Total write: {get_size(disk_io.write_bytes)}\n"
    return reply


def get_gpu_info():
    """
    This function gets the GPU info
    :return: a string with the GPU information divided by \npip list --outdated --format=freeze | Select-String '^\S' | ForEach-Object { $_.Matches.Groups[0].Value } | ForEach-Object { pip uninstall -y $_ }

    """

    reply = "GPU @"
    gpus = GPUtil.getGPUs()
    print("gpus:" + gpus.__str__())
    for gpu in gpus:
        reply += "================"
        # get the GPU id
        reply += f"GPU ID: {gpu.id}\n"
        # name of GPU
        reply += f"Name: {gpu.name}\n"
        # get % percentage of GPU usage of that GPU
        reply += f"Load precent: {gpu.load * 100}%\n"
        # get free memory in MB format
        reply += f"Free memory: {gpu.memoryFree}MB\n"
        # get used memory
        reply += f"Used memory: {gpu.memoryUsed}MB\n"
        # get total memory
        reply += f"Total memory: {gpu.memoryTotal}MB\n"
        # get GPU temperature in Celsius
        reply += f"Temperature: {gpu.temperature} °C\n"
        reply += f"UUID: {gpu.uuid}\n"
    return reply


def get_network_info():
    """
    This function gets the network information
    :return: a string with network information divided by \n
    """

    reply = "Network Information @"
    # get all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        reply += f"=== Interface: {interface_name} ===\n"
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                reply += f"  IP Address: {address.address}\n"
                reply += f"  Netmask: {address.netmask}\n"
                reply += f"  Broadcast IP: {address.broadcast}\n"
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                reply += f"  MAC Address: {address.address}\n"
                reply += f"  Netmask: {address.netmask}\n"
                reply += f"  Broadcast MAC: {address.broadcast}\n"
    # get IO statistics since boot
    net_io = psutil.net_io_counters()
    reply += f"Total Bytes Sent: {get_size(net_io.bytes_sent)}\n"
    reply += f"Total Bytes Received: {get_size(net_io.bytes_recv)}\n"
    return reply


# END OF GET PC INFO FUNCTIONS


def send_able(data):
    while len(data) < 50:
        data = data + " "
    return data


def terminate(name):
    if os.system("TASKKILL /f /im " + name) == 0:
        return True
    else:
        return False


def open_window():
    def validate_ip_address(address):
        try:
            parts = address.split(".")
        except:
            parts = 0
        if len(parts) != 4:
            print("IP address {} is not valid".format(address))
            return False

        for part in parts:
            try:
                num = int(part)
                if not 0 <= num <= 255:
                    print("IP address {} is not valid".format(address))
                    return False
            except ValueError:
                print("IP address {} is not valid".format(address))
                return False

        print("IP address {} is valid".format(address))
        return True

    def validate_login(ip_address_entry, code_entry, connection_win):
        global serverIP, serverCode

        ip_address = ip_address_entry.get()
        serverIP = ip_address
        str_code = code_entry.get()

        if not validate_ip_address(ip_address):
            tk.messagebox.showerror(title="Error", message="Your IP is not valid, please try again.")
            ip_address_entry.delete(0, "end")
            return None

        if not str_code.isdigit():
            tk.messagebox.showerror("Error", "Code must be a number.")
            code_entry.delete(0, "end")
            return None

        serverCode = int(str_code)

        # Запускаем функцию connect_to_server в отдельном потоке
        threading.Thread(target=connect_to_server, args=("Neta & Rafael",)).start()
        connection_win.destroy()

    # LOGIN window
    connection_win = tk.Tk()
    s = ttk.Style()
    s.configure('my.TButton', font=('Helvetica', 14))
    # Gets the requested values of the height and widht.
    windowWidth = connection_win.winfo_reqwidth()
    windowHeight = connection_win.winfo_reqheight()
    print("Width", windowWidth, "Height", windowHeight)

    # Gets both half the screen width/height and window width/height
    positionRight = int(connection_win.winfo_screenwidth() / 2 - windowWidth / 2)
    positionDown = int(connection_win.winfo_screenheight() / 2 - windowHeight / 2)

    # Positions the window in the center of the page.
    connection_win.geometry("+{}+{}".format(positionRight, positionDown))
    connection_win.title('miniTaskManager')
    connection_win.resizable(True, True)

    welcome_label = tk.Label(connection_win, text="Please insert IP Address and Code", font=30, fg="white", bg="blue")
    welcome_label.pack()

    ip_label = tk.Label(connection_win, text="IP Address", font=30)
    ip_label.pack()

    ipaddress = tk.StringVar()
    ip_address_Entry = tk.Entry(connection_win, textvariable=ipaddress, font=30)
    ip_address_Entry.pack(fill="both", padx=10, pady=10)
    #ip_address_Entry.insert(0, "192.168.1.221")

    code_label = tk.Label(connection_win, text="CODE ", font=30)
    code_label.pack()

    code = tk.StringVar()
    code_entry = tk.Entry(connection_win, textvariable=code, font=30)
    code_entry.pack(fill="both", padx=10, pady=10)

    # validateLogin = partial(validate_login, ipaddress, port)
    login_button = ttk.Button(connection_win, text="Connect", style='my.TButton',
                              command=lambda: validate_login(ip_address_Entry, code_entry, connection_win))
    login_button.pack(fill="both", padx=10, pady=10)
    connection_win.mainloop()



def connect_to_server(name):
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((serverIP, server_port))
        client_socket.send(
            str(serverCode).encode())
        res = client_socket.recv(1024).decode()
        if res == "Wrong_code":
            messagebox.showerror("Incorrect code")

            client_socket.close()
        elif res == "success":
            print(socket.gethostbyname(socket.gethostname()))
            client_socket.send(name.encode())
            hold = threading.Thread(target=server_func)
            waiting_window = threading.Thread(target=window)
            waiting_window.start()
            hold.start()

    except socket.error as E:
        print("Can't connect:", E)
        exit()


def server_func():
    reply = ""
    try:
        client_socket.send("command".encode())
        command = client_socket.recv(1024).decode()
    except socket.error as E:
        print("Can't send:", E)
        exit()

    if command != bytes("{quit}", "utf8"):

        if command == "List_all":
            list_of_all = get_processes_info()
            client_socket.send(str(len(list_of_all)).encode())
            response = ""
            for process in list_of_all:
                client_socket.send(pickle.dumps(process))
                response = client_socket.recv(1024).decode()
            response = client_socket.recv(1024).decode()
            if response == "go":
                client_socket.send(pickle.dumps(["sent_all"]))

        while True:
            to_do = pickle.loads(client_socket.recv(4096))
            if to_do[0] == "TERMINATE":
                if terminate(to_do[1]):
                    print("hey")
                    client_socket.send("managed".encode())
                else:
                    client_socket.send("permission_denied".encode())
            if to_do[0] == "List_all":
                list_of_all = get_processes_info()
                client_socket.send(str(len(list_of_all)).encode())
                response = ""
                for process in list_of_all:
                    client_socket.send(pickle.dumps(process))
                    response = client_socket.recv(1024).decode()
                if response == "go":
                    client_socket.send(pickle.dumps(["sent_all"]))
            if to_do[0] == "get_pc_info":
                pc_info = [get_sys_info(),
                           get_boot_time_info(),
                           get_cpu_info(),
                           get_memory_info(),
                           get_swap_memory_info(),
                           get_disk_info(),
                           get_network_info(),
                           get_gpu_info()]
                print("PC INFO " + pc_info.__str__())
                pc_info_str = json.dumps(pc_info)
                client_socket.send(pc_info_str.encode())

            if to_do[0] == "goodbye":
                client_socket.close()
                print("goodbye")
                exit()
    else:
        client_socket.close()


def get_processes_info():
    processes = []
    for process in psutil.process_iter():
        with process.oneshot():
            pid = process.pid
            if pid == 0:
                continue
            name = process.name()
            try:
                create_time = datetime.fromtimestamp(process.create_time())
            except OSError:
                # system processes, using boot time instead
                create_time = datetime.fromtimestamp(psutil.boot_time())
            try:
                # get the number of CPU cores that can execute this process
                cores = len(process.cpu_affinity())
            except psutil.AccessDenied:
                cores = 0
            # get the CPU usage percentage
            cpu_usage = process.cpu_percent()
            # get the status of the process (running, idle, etc.)
            status = process.status()
            try:
                # get the process priority (a lower value means a more prioritized process)
                nice = int(process.nice())
            except psutil.AccessDenied:
                nice = 0
            try:
                # get the memory usage in bytes
                memory_usage = process.memory_full_info().uss
            except psutil.AccessDenied:
                memory_usage = 0
            # total process read and written bytes
            io_counters = process.io_counters()
            read_bytes = io_counters.read_bytes
            write_bytes = io_counters.write_bytes
            # get the number of total threads spawned by this process
            n_threads = process.num_threads()
            # get the username of user spawned the process
            try:
                username = process.username()
            except psutil.AccessDenied:
                username = "N/A"
            to_add = [send_able(str(pid)), send_able(name), send_able(str(create_time)), send_able(str(cores)),
                      send_able(str(cpu_usage)), send_able(status), send_able(str(nice)), send_able(str(memory_usage)),
                      send_able(str(read_bytes)), send_able(str(write_bytes)), send_able(str(n_threads)),
                      send_able(username)]
            processes.append(to_add)
    return processes


def window():
    root = tk.Tk()
    root.title("AFKSupport")
    canvas1 = tk.Canvas(root, width=400, height=100)
    canvas1.pack()
    w = tk.Label(root, text="DON`T SHUT DOWN THE PROGRAM.\n PLEASE WAIT...")
    w.place(relx=0.5, rely=0, anchor='n')
    root.mainloop()


def main():
    open_window()



if __name__ == "__main__":
    main()
