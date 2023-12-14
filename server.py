import socket
import threading
import pickle
import time
import sys
from functools import partial
from tkinter import *
import tkinter.ttk as ttk
from pc_info_wind import PcInfo
from tkinter import messagebox
import random

global list_clients
global addresses

PORT = 5001
HOST = socket.gethostbyname(socket.gethostname())

class MultiListbox(Frame):

    def __init__(self, master, lists):
        Frame.__init__(self, master)
        sb = Scrollbar(self, orient="vertical", command=self.OnVsb)
        sb.pack(side="right", fill="y")
        self.lists = []
        for to_write, w in lists:
            frame = Frame(self, height=40)
            frame.pack(side=LEFT, expand=YES, fill=BOTH)
            Label(frame, text=to_write, borderwidth=1, relief=RAISED).pack(fill=X)
            lb = Listbox(frame, width=w, borderwidth=0, selectborderwidth=0,
                         relief=FLAT, exportselection=FALSE, height=40, yscrollcommand=sb.set)
            lb.pack(expand=YES, fill=BOTH)
            self.lists.append(lb)
            lb.bind("<MouseWheel>", self.OnMouseWheel)
            lb.bind('<B1-Motion>', lambda e, s=self: s._select(e.y))
            lb.bind('<Button-1>', lambda e, s=self: s._select(e.y))
            lb.bind('<Leave>', lambda e: 'break')
            lb.bind('<B2-Motion>', lambda e, s=self: s._b2motion(e.x, e.y))
            lb.bind('<Button-2>', lambda e, s=self: s._button2(e.x, e.y))
        frame = Frame(self)
        frame.pack(side=LEFT, fill=Y)
        Label(frame, borderwidth=1, relief=RAISED).pack(fill=X)

    def delete_all(self):
        """
        This function delets all lines from MultiListbox
        :return:
        """
        names = list(self.lists[1].get(0, END))
        for name in names:
            self.delete_by_name(name)

    def delete_by_name(self, name):
        names = list(self.lists[1].get(0, END))
        i = 0
        while i < len(names):
            if names[i] == name:
                process = self.get_all_process(i)
                self.delete(process)
                names = list(self.lists[1].get(0, END))
                i = 0
            else:
                i = i + 1

    def get_all_process(self, idx):
        """
        This function gets list of processes
        :param idx:
        :return:
        """
        process = []
        for item in self.lists:
            process.append(list(item.get(0, END))[idx])
        return process

    def _select(self, y):
        row = self.lists[0].nearest(y)
        self.selection_clear(0, END)
        self.selection_set(row)
        return 'break'

    def _button2(self, x, y):
        for list1 in self.lists:
            list1.scan_mark(x, y)
        return 'break'

    def _b2motion(self, x, y):
        for list1 in self.lists:
            list1.scan_dragto(x, y)
        return 'break'

    def curselection(self):
        all_selected = []
        for i in range(len(self.lists)):
            current = self.lists[i].curselection()
            total = ""
            for j in current:
                total = total + self.lists[i].get(j)
            all_selected.append(total)
        return all_selected

    def delete(self, process):
        id = list(self.lists[0].get(0, END))
        for i in range(len(process)):
            looking = list(self.lists[i].get(0, END))
            for j in range(len(looking)):
                if looking[j] == process[i] and id[j] == process[0]:
                    self.lists[i].delete(j)

    def index(self, index):
        self.lists[0].index(index)

    def insert(self, index, *elements):
        for e in elements:
            i = 0
            for list1 in self.lists:
                list1.insert(index, e[i])
                i = i + 1

    def size(self):
        return self.lists[0].size()

    def see(self, index):
        for list1 in self.lists:
            list1.see(index)

    def selection_anchor(self, index):
        for list1 in self.lists:
            list1.selection_anchor(index)

    def selection_clear(self, first, last=None):
        for list1 in self.lists:
            list1.selection_clear(first, last)

    def selection_includes(self, index):
        return self.lists[0].selection_includes(index)

    def selection_set(self, first, last=None):
        for list1 in self.lists:
            list1.selection_set(first, last)

    def OnVsb(self, *args):
        self.lists[0].yview(*args)
        self.lists[1].yview(*args)
        self.lists[2].yview(*args)
        self.lists[3].yview(*args)
        self.lists[4].yview(*args)
        self.lists[5].yview(*args)
        self.lists[6].yview(*args)
        self.lists[7].yview(*args)
        self.lists[8].yview(*args)
        self.lists[9].yview(*args)
        self.lists[10].yview(*args)
        self.lists[11].yview(*args)

    def OnMouseWheel(self, event):
        self.lists[0].yview("scroll", -event.delta, "units")
        self.lists[1].yview("scroll", -event.delta, "units")
        self.lists[2].yview("scroll", -event.delta, "units")
        self.lists[3].yview("scroll", -event.delta, "units")
        self.lists[4].yview("scroll", -event.delta, "units")
        self.lists[5].yview("scroll", -event.delta, "units")
        self.lists[6].yview("scroll", -event.delta, "units")
        self.lists[7].yview("scroll", -event.delta, "units")
        self.lists[8].yview("scroll", -event.delta, "units")
        self.lists[9].yview("scroll", -event.delta, "units")
        self.lists[10].yview("scroll", -event.delta, "units")
        self.lists[11].yview("scroll", -event.delta, "units")
        # this prevents default bindings from firing, which
        # would end up scrolling the widget twice
        return "break"


def send_able(data):
    while len(data) < 50:
        data = data + " "
    return data



def create_window():
    global login_code
    log_root = Tk()
    log_root.title("Support Manager")
    log_root.quit()
    canvas1 = Canvas(log_root, width=400, height=200)
    canvas1.pack()
    login_code = random.randint(100000, 999999)
    w = Label(log_root, text="Please tell this info to User for connection! \n  IP ADDRESS:  " +
                             HOST + "\n RANDOM CODE: " + login_code.__str__())
    w.place(relx=0.5, rely=0, anchor='n')
    #log_root.withdraw() close the win

    log_root.mainloop()
    log_root.protocol('WM_DELETE_WINDOW', SERVER.close)






def client_window(client, client_name):
    def get_index(lst, item):
        index = sys.maxsize
        for i, value in enumerate(lst):
            if value == item:
                index = i
        return index

    def sort_by_priority(processes):
        final = []
        prioritys = []
        ids = []
        for item in processes:
            prioritys.append(int(item[6]))
        prioritys.sort()
        for priority in prioritys:
            for proc in processes:
                if priority == int(proc[6]) and get_index(ids, (proc[0])) == sys.maxsize:
                    final.append(proc)
                    ids.append(proc[0])
        return final

    def sort_by_name(processes):
        final = []
        names = []
        ids = []
        for item in processes:
            names.append(item[1].lower())
        names.sort()
        for name1 in names:
            for proc in processes:
                if name1 == proc[1].lower() and get_index(ids, (proc[0])) == sys.maxsize:
                    final.append(proc)
                    ids.append(proc[0])
        return final

    def sort_by_id(processes):
        final = []
        ids = []
        for item in processes:
            ids.append(int(item[0]))
        ids.sort()
        for id1 in ids:
            for proc in processes:
                if id1 == int(proc[0]):
                    final.append(proc)
        return final

    def terminate():
        try:

            selected = mlb.curselection()
            if selected[0] != '':
                process = []
                for item in selected:
                    process.append(item)
                client.send(pickle.dumps(["TERMINATE", process[1]]))
                response = client.recv(1024).decode()
                if response == "managed":
                    mlb.delete_by_name(process[1])
                elif response == "permission_denied":
                    messagebox.showinfo("Attention", "Error to delete")
            else:
                messagebox.showinfo("Attention", "Must to pick line")
        except (socket.error, IndexError) as err:
            print(err)
            print('An error occurred during termination')

    def refresh():
        try:
            all_process1 = []
            client.send(pickle.dumps(["List_all"]))
            length = int(client.recv(1024))
            for i in range(length):
                data = pickle.loads(client.recv(4096))
                client.send("go".encode())
                if data[0] == "sent_all":
                    client.send("done".encode())
                    break
                else:
                    all_process1.append(data)
            client.send("done".encode())
            time.sleep(0.01)
            mlb.delete_all()
            for j in range(len(all_process1)):
                mlb.insert(END, all_process1[j])
        except (socket.error, ValueError) as err:
            print(err)
            print('An error occurred during refresh')

    def close():
        client.send(pickle.dumps(["goodbye"]))
        client.close()
        root.destroy()


    def change_by_priority(all_processes):
        all_processes = sort_by_priority(all_processes)
        mlb.delete_all()
        for i in range(len(all_processes)):
            mlb.insert(END, all_processes[i])

    def change_by_name(all_processes):
        all_processes = sort_by_name(all_processes)
        mlb.delete_all()
        for j in range(len(all_processes)):
            mlb.insert(END, all_processes[j])

    def change_by_id(al_processes):
        al_processes = sort_by_id(al_processes)
        mlb.delete_all()
        for j in range(len(al_processes)):
            mlb.insert(END, al_processes[j])

    root = Tk()
    s = ttk.Style()
    s.configure('my.TButton', font=('Helvetica', 14))
    root.title("AFKSupport-" + client_name)
    root.state('zoomed')
    root.geometry("1400x800")
    root.resizable(True, True)
    label = Label(root, text='process list', width=700)
    label.place(x=0, y=0)
    try:
        is_ready = client.recv(1024).decode() == "command"
        all_process = []
        if is_ready:
            client.send("List_all".encode())
            try:
                length = int(client.recv(1024))
            except socket.error as err:
                print(err)
                print('Please contact your administrator 2')
                sys.exit(-1)
            for i in range(length):
                try:
                    data = pickle.loads(client.recv(4096))
                except socket.error as err:
                    print(err)
                    print('Please contact your administrator 3')
                    sys.exit(-1)
                client.send("go".encode())
                if data[0] == "sent_all":
                    client.send("done".encode())
                    break
                else:
                    all_process.append(data)
            client.send("done".encode())
            mlb = MultiListbox(label, (('Id', 10), ('Name', 20), ('Time', 30), ('Cores', 10), ('Cpu_usage', 20),
                                       ('Status', 20), ('Priority', 10), ('Memory usage', 10), ('Read bytes', 20),
                                       ('Write bytes', 20), ('Threads', 10), ('Username', 25)))
            for j in range(len(all_process)):
                mlb.insert(END, all_process[j])
            mlb.pack(expand=YES, fill=BOTH)
            button = ttk.Button(root,
                                text='Terminate',
                                style='my.TButton',
                                width=30,
                                command=terminate)
            button.place(relx=0.99, rely=0.4, anchor="e")
            button2 = ttk.Button(root,
                                 text='Close connection',
                                 style='my.TButton',
                                 width=30,
                                 command=close)
            button2.place(relx=0.99, rely=0.8, anchor="e")
            change_name = partial(change_by_name, all_process)
            change_id = partial(change_by_id, all_process)
            change_priority = partial(change_by_priority, all_process)
            button3 = ttk.Button(root,
                                 text='Change order by name',
                                 style='my.TButton',
                                 width=30,
                                 command=change_name)
            button3.place(relx=0.99, rely=0.5, anchor="e")
            button4 = ttk.Button(root,
                                 text='Change order by id',
                                 style='my.TButton',
                                 width=30,
                                 command=change_id)
            button4.place(relx=0.99, rely=0.6, anchor="e")
            button5 = ttk.Button(root,
                                 text='Change order by priority',
                                 style='my.TButton',
                                 width=30,
                                 command=change_priority)
            button5.place(relx=0.99, rely=0.7, anchor="e")
            button6 = ttk.Button(root,
                                 text="Refresh",
                                 style='my.TButton',
                                 width=30,
                                 command=refresh)
            button6.place(relx=0.99, rely=0.2, anchor="e")

            button7 = ttk.Button(root,
                                 text="Show PC Info",
                                 style='my.TButton',
                                 width=30,
                                 command=lambda:
                                 PcInfo(client))
            button7.place(relx=0.99, rely=0.2, anchor="e")
        root.mainloop()
    except socket.error as err:
        print(err)
        print('Please contact your administrator 1')
        sys.exit(-1)


def accept_new_clients():
    SERVER.listen(10)
    while True:
        (client, client_address) = SERVER.accept()
        print("Connected: %s:%s" % client_address)
        client_code = client.recv(1024).decode()
        print(login_code)
        if int(client_code) == login_code:
            print("equal: "+client_code)
            client.send("success".encode())
            client_name = client.recv(1024).decode()
            list_clients.append(client)
            addresses[client] = client_address
            handle_client = threading.Thread(target=client_window, args=(client, client_name))
            handle_client.start()
        else:
            client.send("Wrong_code".encode())
            client.close()




def main():
    global SERVER
    global list_clients
    global addresses
    list_clients = []
    addresses = {}

    try:
        address = (HOST, PORT)
        SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SERVER.bind(address)
        print("Listening...")
        create_window_thread = threading.Thread(target=create_window)
        create_window_thread.daemon = True
        create_window_thread.start()

        # Запустить поток accept_new_clients
        accept_clients_thread = threading.Thread(target=accept_new_clients)
        accept_clients_thread.daemon = True
        accept_clients_thread.start()

        create_window_thread.join()
        accept_clients_thread.join()
        SERVER.close()
        print("Сервер закрыт")
        sys.exit(0)
    except socket.error as err:
        print(err)
        print('Ошибка создания сервера')
        sys.exit(0)



if __name__ == "__main__":
    main()