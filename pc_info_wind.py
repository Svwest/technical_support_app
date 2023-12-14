import socket
import pickle
import sys
import tkinter
from tkinter import *
import tkinter.ttk as ttk
import json

global SERVER



class PcInfo:
    def __init__(self, client_socket):

        root_pc = tkinter.Tk()
        root_pc.title("Computer Info ")
        root_pc.geometry("732x712+375+10")
        root_pc.configure(bg="green")



        # create top menubar
        menubar = tkinter.Menu(root_pc)

        helpmenu = tkinter.Menu(menubar, tearoff=0)
        #helpmenu.add_command(label="Help", command=show_root_help)
        #helpmenu.add_command(label="About", command=show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        root_pc.config(menu=menubar)

        # create tabs menu

        tabControl = ttk.Notebook(root_pc)
        tabControl.pack(expand=1, fill="both")

        tab1 = ttk.Frame(tabControl)
        tab2 = ttk.Frame(tabControl)
        tab3 = ttk.Frame(tabControl)
        tab4 = ttk.Frame(tabControl)
        tab5 = ttk.Frame(tabControl)
        tab6 = ttk.Frame(tabControl)
        tab7 = ttk.Frame(tabControl)
        tab8 = ttk.Frame(tabControl)

        tab_list = [tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8]


        ##logos = ImageTk.PhotoImage(Image.open("logos_row3.png"))
        ##logos1 = ttk.Label(tab1, image=logos, bg="black")
        ##logos1.grid(column=0, row=0)
        ##logos2 = ttk.Label(tab1, image=logos, bg="black")
        ##logos2.grid(column=0, row=4)

        def get_pc_info():
            client_socket.send(pickle.dumps(["get_pc_info"]))
            try:
                received_data = client_socket.recv(4096).decode()
            except socket.error as err:
                print(err)
                print('Please contact your administrator')
                sys.exit(-1)
            pc_info = json.loads(received_data)
            return pc_info

        print(get_pc_info())

        def display_pc_info():
            pc_info = get_pc_info()

            # clear the tabs
            for tab in [tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8]:
                for widget in tab.winfo_children():
                    widget.destroy()

            # putting pc info to tabs and their titles
            for i, sublist in enumerate(pc_info):

                key_pop = sublist.split('@')
                tabControl.add(tab_list[i], text=key_pop[0])
                text_widget = Text(tabControl.winfo_children()[i], wrap="none", height=20, width=60)
                text_widget.insert("1.0", key_pop[1])
                text_widget.pack()

        display_pc_info()

