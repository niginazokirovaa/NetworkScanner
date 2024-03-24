import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import *

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        # Новые цвета и стили
        bg_color = "#f0f0f0"
        text_color = "#333333"
        button_color = "#ff66b3"
        button_text_color = "#ffffff"

        # Фрейм для группировки элементов интерфейса
        self.frame = tk.Frame(root, bg=bg_color)
        self.frame.pack(padx=10, pady=10)

        # Метка для разрешенных IP-адресов
        self.label_moderated = tk.Label(self.frame, text="Разрешенные IP адреса:", font=("Arial", 12), bg=bg_color, fg="#00ff7f")
        self.label_moderated.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Список для разрешенных IP-адресов
        self.listbox_moderated = tk.Listbox(self.frame, width=50, height=10, bg="white", fg=text_color)
        self.listbox_moderated.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        # Вертикальный скроллбар для списка разрешенных IP-адресов
        self.scrollbar_moderated = tk.Scrollbar(self.frame, orient='vertical', command=self.listbox_moderated.yview)
        self.scrollbar_moderated.grid(row=1, column=1, sticky="ns")
        self.listbox_moderated.config(yscrollcommand=self.scrollbar_moderated.set)

        # Метка для заблокированных IP-адресов
        self.label_blocked = tk.Label(self.frame, text="Заблокированные IP адреса:", font=("Arial", 12), bg=bg_color, fg="#ff0000")
        self.label_blocked.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        # Список для заблокированных IP-адресов
        self.listbox_blocked = tk.Listbox(self.frame, width=50, height=10, bg="white", fg=text_color)
        self.listbox_blocked.grid(row=1, column=2, padx=10, pady=5, sticky="nsew")

        # Вертикальный скроллбар для списка заблокированных IP-адресов
        self.scrollbar_blocked = tk.Scrollbar(self.frame, orient='vertical', command=self.listbox_blocked.yview)
        self.scrollbar_blocked.grid(row=1, column=3, sticky="ns")
        self.listbox_blocked.config(yscrollcommand=self.scrollbar_blocked.set)

        # Кнопка для начала сканирования
        self.start_button = tk.Button(self.frame, text="Начать сканирование", font=("Arial", 12), bg=button_color, fg=button_text_color, command=self.start_scan)
        self.start_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Кнопка для остановки сканирования
        self.stop_button = tk.Button(self.frame, text="Остановить сканирование", font=("Arial", 12), bg=button_color, fg=button_text_color, command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=2, columnspan=2, padx=10, pady=10)

        # Многострочное текстовое поле для вывода сообщений
        self.text = scrolledtext.ScrolledText(root, fg=text_color, font=("Courier", 12), bg="white")
        self.text.pack(expand=True, fill='both', padx=10, pady=10)

        self.running = False
        self.suspicious_ips = set()

    def start_scan(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.listbox_moderated.delete(0, tk.END)
        self.listbox_blocked.delete(0, tk.END)
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, "Сканирование запущено...\n")

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_scan(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text.insert(tk.END, "Сканирование завершено.\n")

    def sniff_packets(self):
        while self.running:
            sniff(filter="", prn=self.analyze_packet, count=1)

    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                self.suspicious_ips.add(ip_src)
                message = f"Suspicious TCP packet from {ip_src}:{tcp_sport} to {ip_dst}:{tcp_dport}\n"
                self.update_text(message)
                if ip_src.endswith('.256') or ip_dst.endswith('.256'):
                    self.listbox_blocked.insert(tk.END, f"{ip_src} -> {ip_dst}")
                    self.listbox_blocked.yview(tk.END)
                else:
                    self.listbox_moderated.insert(tk.END, f"{ip_src} -> {ip_dst}")
                    self.listbox_moderated.yview(tk.END)
            elif packet.haslayer(UDP):
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                self.suspicious_ips.add(ip_src)
                message = f"Suspicious UDP packet from {ip_src}:{udp_sport} to {ip_dst}:{udp_dport}\n"
                self.update_text(message)
                if  ip_src.endswith('.17') or ip_dst.endswith('.17'):
                    self.listbox_blocked.insert(tk.END, f"{ip_src} -> {ip_dst}")
                    self.listbox_blocked.yview(tk.END)
                else:
                    self.listbox_moderated.insert(tk.END, f"{ip_src} -> {ip_dst}")
                    self.listbox_moderated.yview(tk.END)

    def update_text(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
