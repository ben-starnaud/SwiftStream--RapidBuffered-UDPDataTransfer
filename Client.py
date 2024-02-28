import threading
import socket
import time
import struct
import tkinter as tk
import os
import time
from tkinter import Toplevel
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from PIL import ImageTk, Image

HOST = ''
PORT = 1234
TCP_PORT = 1235
recipients = ['25.22.165.213']
BLAST_SIZE = 1024
TIMEOUT = 0.1
TERMINATION_PACKET = b'0000'
TO = 0
TOTAL = 0
T2 = 0
TOTAL2 = 0
PROGRESS = 0


# Send a termination packet to indicate that it is the end of the file
def send_termination_packet(tcp_conn):
    tcp_conn.sendall(TERMINATION_PACKET)

# Function to receive files using TCP
# param: progress_bar - it is taken in as an argument so that 
# it could be set to the file size
# update_progress - taken in as an argument to update the 
# progress bar
def TCP_receive(progress_bar, update_progress):
    TCP_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket to receive the file
    TCP_receive_socket.bind((HOST, PORT))
    TCP_receive_socket.listen(1)
    while True:
        peer, peer_addr = TCP_receive_socket.accept() # Accept an incoming connection
        full_path = peer.recv(1024).decode()
        filename = os.path.basename(full_path) # Get the file's full path, name, and size
        file_size = int(peer.recv(1024).decode())
        progress_bar["maximum"] = file_size # Set the progress bar's maximum value to the file size
        print(filename)
        try:
            with open(filename, 'wb') as f: # Save the received file
                received_bytes = 0
                while True:
                    filedata = peer.recv(1024)
                    if not filedata:
                        break
                    received_bytes += len(filedata)
                    update_progress(received_bytes) # Update the progress bar 
                    f.write(filedata)
            peer.close() # Close the connection
            print(f"File '{filename}' received from {peer_addr[0]} with TCP") 
            progress_bar['value'] = 0
            root.update_idletasks()
        except Exception as e:
            print(f"Error receiving file '{filename}': {e}")

# Function to send files using TCP
# param: progress_bar - it is taken in as an argument so that it 
# could be updated 
def TCP_send(progress_bar):
    TO = time.time()
    filename = FILENAME
    print(FILENAME)
    try:
        with open(FILENAMETEMP, 'rb') as f: # Read the file to be sent
            file_size = os.path.getsize(FILENAMETEMP)
            filedata = f.read() 
            progress_bar['maximum'] = file_size # Set the progress bar's maximum value to the file size
            for recipient in recipients:
                try:
                    TCP_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket to send the file
                    TCP_send_socket.connect((recipient, PORT))
                    TCP_send_socket.send(filename.encode()) # Send the file name and size
                    time.sleep(1)
                    TCP_send_socket.send(str(file_size).encode())
                    time.sleep(1)
                    
                    # Send the file in chunks
                    bytes_sent = 0
                    with open(FILENAMETEMP, 'rb') as file:
                        while (chunk := file.read(1024)):
                            TCP_send_socket.sendall(chunk)
                            bytes_sent += len(chunk)
                            progress_bar['value'] = bytes_sent
                            root.update_idletasks()

                    t1 = time.time() # Calculate the total time taken and print the result
                    TOTAL = t1 - TO
                    print(TOTAL)
                    print(f"File '{filename}' sent to {recipient}")
                    #progress_bar['value'] = 0
                    #root.update_idletasks()
                except Exception as e:
                    print(f"Error sending file to {recipient}: {e}")
                finally:
                    TCP_send_socket.close()
    except Exception as e:
        print(f"Error opening file '{filename}': {e}")


# Function to receive files using RBUDP
# param: progress_bar - it is taken in as an argument so that 
# it could be set to the file size
# update_progress - taken in as an argument to update the 
# progress bar
def RBUDP_receive(progress_bar, update_progress):
    TCP_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket for signaling, receiving the file size and filename
    TCP_receive_socket.bind((HOST, TCP_PORT))
    TCP_receive_socket.listen(1)

    while True:
        tcp_conn, tcp_peer_addr = TCP_receive_socket.accept() # Accept the connection
        udp_filename = tcp_conn.recv(1024).decode()
        filesize = struct.unpack("!Q", tcp_conn.recv(8))[0]

        if udp_filename:
            received_data = {} # Initialize received_data structure to store received data
            expected_seq_number = 1
            UDP_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create a UDP socket to receive file
            UDP_receive_socket.bind((HOST, PORT))

            while True:
                try:
                    UDP_receive_socket.settimeout(TIMEOUT) # Set a timeout for the UDP socket to handle potential packet loss
                    udp_data, udp_peer_addr = UDP_receive_socket.recvfrom(BLAST_SIZE + 4)
                    packet_seq_number, packet_data = struct.unpack("!I", udp_data[:4])[0], udp_data[4:] # Unpack the received data to obtain the sequence number and payload

                    received_data[packet_seq_number] = packet_data

                    if packet_seq_number == expected_seq_number: # If packet's sequence number = expected sequence number, update the progress bar
                        expected_seq_number += 1
                        update_progress((sum([len(data) for data in received_data.values()]) / filesize) * 100) # Update the progress bar

                    tcp_conn.sendall(struct.pack("!I", expected_seq_number)) # Send an ack to the sender

                    if len(packet_data) < BLAST_SIZE: # If packet_data length < BLAST_SIZE, it is the last packet and the termination packet will be sent
                        send_termination_packet(tcp_conn)
                        break
                except socket.timeout:
                    if expected_seq_number in received_data: # If there's a timeout and the expected sequence number is in the received_data dictionary, break the loop
                        break

            try:
                with open(udp_filename, 'wb') as f:
                    for i in sorted(received_data):
                        f.write(received_data[i])
                    print(f"File '{udp_filename}' received from {udp_peer_addr[0]} with RBUDP")
                    progress_bar['value'] = 0
                    root.update_idletasks()
            except Exception as e:
                print(f"Error receiving file '{udp_filename}': {e}")
            finally:
                tcp_conn.close() 
                UDP_receive_socket.close() # Close the connection

# Function to send files using UDP
# param: progress_bar - it is taken in as an argument so that it 
# could be updated 
def RBUDP_send(progress_bar):
    T2 = time.time()
    filename = FILENAME
    filesize = os.path.getsize(FILENAMETEMP)
    bytes_sent = 0

    try:
        with open(FILENAMETEMP, 'rb') as f: # Read the file to be sent
            filedata = f.read()

            for recipient in recipients:
                try:
                    TCP_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket for signaling and sending file name and size
                    TCP_send_socket.connect((recipient, TCP_PORT))
                    TCP_send_socket.sendall(filename.encode()) # Sned the file name and size
                    time.sleep(1)
                    TCP_send_socket.sendall(struct.pack("!Q", filesize))
                    time.sleep(1)

                    UDP_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create a UDP socket to send the file
                    UDP_send_socket.connect((recipient, PORT))

                    seq_number = 1
                    last_ack = 0
                    while seq_number <= last_ack + 1: # Continue sending data until the sender acknowledges all packets
                        try:
                            TCP_send_socket.settimeout(TIMEOUT) # Timeout for  the TCP socket to handle potential packet loss
                            chunk = filedata[(seq_number-1) * BLAST_SIZE: seq_number * BLAST_SIZE]
                            packet_data = struct.pack("!I", seq_number) + chunk # Create a packet with the current sequence number and chunk data
                            UDP_send_socket.sendto(packet_data, (recipient, PORT))
                            recv_data = TCP_send_socket.recv(4)
                            if recv_data == TERMINATION_PACKET:  # Check for termination packet and break the loop if received
                                break

                            if len(recv_data) == 4: # If the received ack length is 4 bytes, process it
                                ack = struct.unpack("!I", recv_data)[0]
                                if ack > last_ack: # If the ack number is greater than the last ack, update the last_ack and seq_number
                                    last_ack = ack
                                    seq_number += 1
                                    bytes_sent += len(chunk)
                                    progress_bar['value'] = bytes_sent / filesize * 100 # Update the progress bar 
                                    root.update_idletasks()
                                else:
                                    continue
                        except socket.timeout:
                            continue
                    T3 = time.time() # Calculate the total time taken and print the result
                    TOTAL2 = T3 - T2
                    print(TOTAL2)
                    ClientGUI.create_time2
                    print(f"File '{filename}' sent to {recipient}")
                    #progress_bar['value'] = 0
                    #root.update_idletasks()
                except Exception as e:
                    print(f"Error sending file to {recipient}: {e}")
                finally:
                    TCP_send_socket.close() # Close all the sockets
                    UDP_send_socket.close()
    except Exception as e:
        print(f"Error opening file '{filename}': {e}")

# This is for setting up the GUI
class ClientGUI:
    def __init__(self, window):
        self.master = window
        window.title("Stellies Swap")  # Title of the GUI
        window.geometry("800x400")

        self.master.configure(bg='azure4')

        self.my_logo = ImageTk.PhotoImage(Image.open('image/logo.jpg'))
        my_label = Label(image=self.my_logo)
        my_label.pack()

        self.master.after(1200, self.hide_image)

        self.transfer_label = None
        self.tcp_button = None
        self.rbudp_button = None
        self.progress_bar = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate')
        self.progress_bar2 = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate')

    def hide_image(self):
        for widget in self.master.winfo_children(): # Remove the label containing the image
            if isinstance(widget, Label):
                widget.destroy()

        self.transfer_button = Button(text="Select a file", command=self.transfer_file, width=15, height=1, font=("Arial", 20)) # Add the transfer button
        self.transfer_button.place(x=20, y=20)
       
        self.file_path_text = Text(self.master, width=55, height=1, state='disabled') # Add the file path option box
        self.file_path_text.place(x=300, y=27)
        
        self.transfer_label = Label(self.master, text="PROGRESS:", font=("Arial, 20"), bg='azure4') # Add Receive text
        self.transfer_label.place(x=20, y=135)
        
        self.transfer_label = Label(self.master, text="Transfer type: TCP", font=("Arial, 10"), bg='azure4') # Add the text below progress bar
        self.transfer_label.place(x=100, y=190)

        self.transfer_label = Label(self.master, text="Transfer type: RBUDP", font=("Arial, 10"), bg='azure4') # Add the text below progress bar
        self.transfer_label.place(x=100, y=265)
        
        self.tcp_button = Button(text="Send File", command=self.transfer, width=15, height=1, font=("Arial", 20)) # Add the transfer button
        self.tcp_button.place(x=20, y=75)

        self.progress_bar = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate') # Add the progress bar receive
        self.progress_bar.place(x=300, y=190)

        self.progress_bar2 = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate') # Add the progress bar receive
        self.progress_bar2.place(x=300, y=265)

    def transfer_file(self):
        global FILENAMETEMP
        global FILENAME
        file_path = filedialog.askopenfilename() # Show the file selection dialog
        FILENAMETEMP = file_path
        FILENAME = file_path[file_path.rfind('/')+1:]

        self.file_path_text.config(state='normal')
        self.file_path_text.delete(1.0, END)
        self.file_path_text.insert(END, file_path) # Update the file path option box
        self.file_path_text.config(state='disabled')

    def create_time(self):
        self.transfer_label = Label(self.master, text=TOTAL , font=("Arial, 10"), bg='CadetBlue1')
        self.transfer_label.place(x=80, y=280)

    def create_time2(self):
        self.transfer_label = Label(self.master, text=TOTAL2 , font=("Arial, 10"), bg='CadetBlue1')
        self.transfer_label.place(x=80, y=200)

    def transfer(self):
        send_threadTCP = threading.Thread(target=lambda: TCP_send(self.progress_bar))
        send_threadTCP.start()
        
        send_threadRBUDP = threading.Thread(target=lambda: RBUDP_send(self.progress_bar2))
        send_threadRBUDP.start()

        self.progress_bar['value'] = 0
        self.progress_bar2['value'] = 0

    def get_progress_bars(self):
        return self.progress_bar, self.progress_bar2

    def update_progress(self, value):
        self.progress_bar['value'] = value
        self.master.update_idletasks()

    def update_progress2(self, value):
        self.progress_bar2['value'] = value
        self.master.update_idletasks()

# Main to start the program    
def main():
    global root
    root = tk.Tk()
    app = ClientGUI(root)
    progress_bar, progress_bar2 = app.get_progress_bars()
    receive_thread = threading.Thread(target=lambda: TCP_receive(progress_bar2, app.update_progress))
    receive_thread.start()

    receive_thread = threading.Thread(target=lambda: RBUDP_receive(progress_bar, app.update_progress2))
    receive_thread.start()
    root.mainloop()

if __name__ == '__main__':
    main()

