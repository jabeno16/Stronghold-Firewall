import tkinter
import tkinter as tk
import customtkinter
from tkinter import messagebox
from tkinter import ttk
from tkinter import PhotoImage
from tkinter import messagebox
import subprocess
import threading

window1 = customtkinter.CTk()
window1.geometry("500x550")
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("green")


def check_credentials():
    # Open the file containing the username and password
    with open('credentials.txt') as f:
        # Read the first line as the username and second line as the password
        correct_username = f.readline().strip()
        correct_password = f.readline().strip()

        entered_username = username_entry.get()
        entered_password = right_password.get()

        # Check if the entered username and password match the correct ones
        if entered_username == correct_username and entered_password == correct_password:
            messagebox.showinfo('Success', 'Login successful!')
            window1.destroy()
        else:
            messagebox.showerror('Error', 'Incorrect username or password')


def login():
    pass


frame = customtkinter.CTkFrame(master=window1)
frame.pack(pady=20, padx=60, fill="both", expand=True)

label = customtkinter.CTkLabel(master=frame, text="Stronghold Firewall", font=("Roboto", 28))
label.pack(pady=12, padx=10)

username_entry = customtkinter.CTkEntry(master=frame, placeholder_text="Username", font=("Roboto", 16))
username_entry.pack(pady=12, padx=10)

right_password = customtkinter.CTkEntry(master=frame, placeholder_text="Password", show="*", font=("Roboto", 16))
right_password.pack(pady=12, padx=10)

button = customtkinter.CTkButton(master=frame, text="Login", command=check_credentials)
button.pack(pady=12, padx=10)

logo = PhotoImage(file="/home/kali/Stronghold_firewall/custom/logo.png")
label = tk.Label(frame, image=logo)
label.place(x=90, y=250)

window1.mainloop()


# Position the label under the login button


def event_order():
    subnet_mask = Source_IP_entry.get()
    source_ip_address = Source_IP_entry.get()
    submit_ip_address(source_ip_address, subnet_mask)

    dsubnet = DST_IP_entry.get()
    destination_ip_address = DST_IP_entry.get()
    submitdest_ip_address(destination_ip_address, dsubnet)

    enter_data()

    sourceport = SRC_port_entry.get()
    sourceportcheck(sourceport)

    dstport = DST_port_entry.get()
    destinationportcheck(dstport)


def enter_data():
    inbound_dir = accept_IN.get()
    outbound_dir = accept_OUT.get()
    bi_dir = accept_both.get()

    Action = Action_combobox.get()
    Protocol = Protocol_combobox.get()
    sourceIP = Source_IP_entry.get()
    sourceport = SRC_port_entry.get()
    destinationip = DST_IP_entry.get()
    destinationport = DST_port_entry.get()

    # if Action and Protocol and sourceIP and sourceport and destinationip and destinationport:
    SourceIP = Source_IP_entry.get()
    SCRport = SRC_port_entry.get()
    DSTIP = DST_IP_entry.get()
    DSTport = DST_port_entry.get()

    if inbound_dir == "Accepted" and outbound_dir == "Accepted":
        tkinter.messagebox.showwarning(title="Error", message="Only one Box for Traffic Direction can be "
                                                              "Selected, Try again!")
        return
    if outbound_dir == "Accepted" and bi_dir == "Accepted":
        tkinter.messagebox.showwarning(title="Error", message="Only one Box for Traffic Direction can be "
                                                              "Selected, Try again!")
        return
    if inbound_dir == "Accepted" and bi_dir == "Accepted":
        tkinter.messagebox.showwarning(title="Error", message="Only one Box for Traffic Direction can be "
                                                              "Selected, Try again!")
        return
    if inbound_dir == "Accepted" and Action and SourceIP and DSTIP:
        if DSTport == "None" or DSTport == "ANY":
            if SCRport == "None" or SCRport == "ANY":
                if Protocol == "None" or Protocol == "ANY":
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP)
                    return
                else:
                    # if DSTport != "None" or DSTport != "ANY":
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port",
                          ("{}/{}".format(str(DSTport), str(Protocol))))
                    return
            else:
                if Protocol == "None" or Protocol == "ANY":
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", SCRport)
                    return
                else:
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", SCRport, Protocol)
                    return
        else:
            if SCRport == "None" or SCRport == "ANY":
                if Protocol == "None" or Protocol == "ANY":
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", DSTport)
                    return
                else:
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", DSTport, Protocol)
                    return
            else:
                if Protocol == "None" or Protocol == "ANY":
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", DSTport, "port", SCRport)
                    return
                else:
                    print("sudo", "ufw", Action, "from", SourceIP, "to", DSTIP, "port", DSTport, "port", SCRport,
                          Protocol)
                    return

    if outbound_dir == "Accepted":
        print("sudo", "ufw", Action, "Out", SourceIP, SCRport, "to", DSTIP, DSTport, Protocol)
        return
    if bi_dir == "Accepted":
        print("route", Action, SourceIP, SCRport, DSTIP, DSTport, Protocol)
        return
    else:
        tkinter.messagebox.showwarning(title="Error", message="More Info Needed")


window2 = tkinter.Tk()
window2.title("Stronghold Firewall")

frame = tkinter.Frame(window2)
frame.pack()

user_info_frame = tkinter.LabelFrame(frame, text="Create UFW Rule")
user_info_frame.grid(row=0, column=0, padx=20, pady=10)

Action_label = tkinter.Label(user_info_frame, text="Action")
Action_label.grid(row=0, column=0)
Action_combobox = ttk.Combobox(user_info_frame,
                               values=["allow", "deny"])
Action_combobox.grid(row=1, column=0)

Protocol_label = tkinter.Label(user_info_frame, text="Protocol")
Protocol_label.grid(row=0, column=1)
Protocol_combobox = ttk.Combobox(user_info_frame,
                                 values=["ANY", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "FTP", "FTPS",
                                         "IMAP", "POP3", "RDP", "SIP", "SMB", "SMTP", "SNMP", "SSH", "Telnet", "VNC",
                                         "None"])
Protocol_combobox.grid(row=1, column=1)

Source_IP_label = tkinter.Label(user_info_frame, text="Source IP Address")
Source_IP_entry = ttk.Combobox(user_info_frame, values=["ANY", "None"])
Source_IP_label.grid(row=0, column=2)
Source_IP_entry.grid(row=1, column=2)

SRC_port_label = tkinter.Label(user_info_frame, text="Source port")
SRC_port_label.grid(row=2, column=0)
SRC_port_entry = ttk.Combobox(user_info_frame, values=["ANY", "None"])
SRC_port_entry.grid(row=3, column=0)

DST_IP_label = tkinter.Label(user_info_frame, text="Destination IP Address")
DST_IP_label.grid(row=2, column=1)
DST_IP_entry = ttk.Combobox(user_info_frame, values=["ANY", "None"])
DST_IP_entry.grid(row=3, column=1)

DST_port_label = tkinter.Label(user_info_frame, text="Destination port")
DST_port_label.grid(row=2, column=2)
DST_port_entry = ttk.Combobox(user_info_frame, values=["ANY", "None"])
DST_port_entry.grid(row=3, column=2)

for widget in user_info_frame.winfo_children():
    widget.grid_configure(padx=10, pady=5)

terms_frame = tkinter.LabelFrame(frame, text="Traffic Direction")
terms_frame.grid(row=2, column=0, sticky="news", padx=20, pady=10)

accept_IN = tkinter.StringVar(value="Not Accepted")
inbound = tkinter.Checkbutton(terms_frame, text="Inbound",
                              variable=accept_IN, onvalue="Accepted", offvalue="Not Accepted")
accept_OUT = tkinter.StringVar(value="Not Accepted")
outbound = tkinter.Checkbutton(terms_frame, text="Outbound",
                               variable=accept_OUT, onvalue="Accepted", offvalue="Not Accepted")
accept_both = tkinter.StringVar(value="Not Accepted")
bidirectional = tkinter.Checkbutton(terms_frame, text="Bi-Directional",
                                    variable=accept_both, onvalue="Accepted", offvalue="Not Accepted")
inbound.grid(row=0, column=0)
outbound.grid(row=0, column=2)
bidirectional.grid(row=0, column=3)

button = tkinter.Button(frame, text="Create New Rule", command=event_order)
button.grid(row=3, column=0, sticky="news", padx=20, pady=10)


def show_all_ufw_rules():
    rules_window = tk.Toplevel(window2)
    ufw_rules = subprocess.run(["sudo", "ufw", "status", "numbered"], stdout=subprocess.PIPE)
    rules_text = ufw_rules.stdout.decode()
    rules_label = tk.Label(rules_window, text=rules_text)
    rules_label.pack()


button = tk.Button(frame, text="Show All UFW Rules \n (Root is required)", command=show_all_ufw_rules)
button.grid(row=4, column=0, sticky="news", padx=20, pady=10)


def inboundhelp():
    rules_window = tk.Toplevel(window2)
    ufw_rules = subprocess.run(["cat", "syntaxhelp.txt"], stdout=subprocess.PIPE)
    rules_text = ufw_rules.stdout.decode()
    rules_label = tk.Label(rules_window, text=rules_text)
    rules_label.pack()


button = tk.Button(frame, text="Syntax Help", command=inboundhelp)
button.grid(row=5, column=0, sticky="news", padx=20, pady=10)

frame = tk.Frame(window2)
frame.pack()
rules = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True).stdout

# Split the output into lines and remove the first two lines (which are headers)
rules = rules.split("\n")[2:]

# Create a list of rules with the number and rule syntax
rules = [f"{i}: {rule}" for i, rule in enumerate(rules, start=1)]

# Create a ComboBox widget with the list of rules, specifying the frame as its master
combo = tk.ttk.Entry(frame)
combo.pack()


def on_button_click():
    selected_rule = combo.get()
    if selected_rule:
        # Extract the number of the selected rule
        rule_number = selected_rule.split(":")[0]
        # Run the `ufw delete` command with the number of the selected rule
        subprocess.run(["sudo", "ufw", "delete", rule_number])


button = tk.Button(frame, text="Delete Selected Rule", command=on_button_click)
button.pack()


def update_rules():
    global rules, combo
    # Run the `ufw status numbered` command to get a list of updated rules
    rules = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True).stdout
    # Split the output into lines and remove the first two lines (which are headers)
    rules = rules.split("\n")[2:]
    # Create a list of rules with the number and rule syntax
    rules = [f"{i}: {rule}" for i, rule in enumerate(rules, start=1)]


def submit_ip_address(source_ip_address, subnet_mask):
    octets = source_ip_address.split('.')
    subnet_octets = subnet_mask.split('.')

    if source_ip_address == "ANY":
        return
    if len(octets) != 4:
        tkinter.messagebox.showwarning(title="ERROR", message="Invalid IP Address or Subnet Mask")
    elif len(octets) == 4:
        for octet, subnet_octet in zip(octets, subnet_octets):
            try:
                int_octet = int(octet)
                int_subnet_octet = int(subnet_octet)
                if 0 < int_octet > 255:
                    tkinter.messagebox.showwarning(title="ERROR", message="Source out of range")

                    if 0 > int_subnet_octet > 32:
                        tkinter.messagebox.showwarning(title="ERROR", message="Invalid IPp Address or Subnet Mask")
            except ValueError:
                tkinter.messagebox.showwarning(title="ERROR", message="Invalid IPpp Address or Subnet Mask")
            network_address = [str(int_octet & int_subnet_octet) for octet, subnet_octet in zip(octets, subnet_octets)]
            network_address = '.'.join(network_address)
            return network_address


def submitdest_ip_address(destination_ip_address, dsubnet):
    octets = destination_ip_address.split('.')
    subnet_octets = dsubnet.split('.')

    if destination_ip_address == "ANY":
        return
    elif len(octets) != 4:
        tkinter.messagebox.showwarning(title="ERROR", message="Invalid Destination IP Address Syntax")
    if destination_ip_address != "ANY":
        for octet, subnet_octet in zip(octets, subnet_octets):
            try:
                int_octet = int(octet)
                int_subnet_octet = int(subnet_octet)
                if int_octet < 0 or int_octet > 255:
                    if int_subnet_octet < 0 or int_subnet_octet > 32:
                        tkinter.messagebox.showwarning(title="ERROR", message="Invalid Destination IP Address Range")
            except ValueError:
                tkinter.messagebox.showwarning(title="ERROR", message="Invalid IP Address or Subnet Mask")
            network_address = [str(int_octet & int_subnet_octet) for octet, subnet_octet in zip(octets, subnet_octets)]
            network_address = '.'.join(network_address)
            return network_address


def sourceportcheck(sourceport):
    srcport = sourceport
    if srcport == "":
        tkinter.messagebox.showwarning(title="Error", message="Port is required")
    if srcport == "None":
        return
    if srcport == "any" or srcport == "ANY":
        return
    elif srcport != "any" or srcport != "ANY":
        srcport = int(srcport)
        if srcport < 0 or srcport > 65535:
            tkinter.messagebox.showwarning(title="Error", message="Source Port is out of Range!")
        else:
            return


def destinationportcheck(dstport):
    dstport = dstport
    if dstport == "":
        tkinter.messagebox.showwarning(title="Error", message="Port is required")
    if dstport == "None":
        return
    if dstport == "any" or dstport == "ANY":
        return
    elif dstport != "any" or dstport != "ANY":
        dstport = int(dstport)
        if dstport < 0 or dstport > 65535:
            tkinter.messagebox.showwarning(title="Error", message="Destination Port is out of Range!")
        else:
            return


window2.mainloop()


def exit_program():
    window2.destroy()

