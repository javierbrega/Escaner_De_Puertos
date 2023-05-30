import tkinter as tk
from tkinter import messagebox
import nmap
from tkinter import ttk
from threading import Thread


class PortScannerApp:
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.title("Escaneo de Puertos - Javier Brega")
        self.ventana.configure(bg='white')

        self.ip_label = tk.Label(self.ventana, text="Dirección IP:", bg='white')
        self.ip_label.pack()
        self.ip_entry = tk.Entry(self.ventana)
        self.ip_entry.pack()

        self.puerto_inicial_label = tk.Label(self.ventana, text="Puerto Inicial:", bg='white')
        self.puerto_inicial_label.pack()
        self.puerto_inicial_entry = tk.Entry(self.ventana)
        self.puerto_inicial_entry.pack()

        self.puerto_final_label = tk.Label(self.ventana, text="Puerto Final:", bg='white')
        self.puerto_final_label.pack()
        self.puerto_final_entry = tk.Entry(self.ventana)
        self.puerto_final_entry.pack()

        self.button_frame = tk.Frame(self.ventana, bg='white')
        self.button_frame.pack()

        self.escanear_button = tk.Button(self.button_frame, text="Escanear", command=self.escanear_puertos,
                                         bg='lightblue', fg='black')
        self.escanear_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.suspender_button = tk.Button(self.button_frame, text="Suspender", command=self.suspender_escaneo,
                                          bg='lightgreen', fg='black')
        self.suspender_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.suspender_button.config(state=tk.DISABLED)

        self.limpiar_button = tk.Button(self.button_frame, text="Limpiar", command=self.limpiar_pantalla,
                                        bg='lightcoral', fg='black')
        self.limpiar_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.limpiar_button.config(state=tk.DISABLED)

        self.progreso = ttk.Progressbar(self.ventana, mode="determinate")
        self.progreso.pack()

        self.informe_text = tk.Text(self.ventana, height=10, width=70)
        self.informe_text.pack()

        self.nm = nmap.PortScanner()
        self.hilo_escaneo = None

    def escanear_puertos(self):
        direccion_ip = self.ip_entry.get()
        puerto_inicial = int(self.puerto_inicial_entry.get())
        puerto_final = int(self.puerto_final_entry.get())

        resultados = []

        nm = nmap.PortScanner()

        scan_range = f"{puerto_inicial}-{puerto_final}"
        nm.scan(direccion_ip, arguments=f"-p {scan_range} -T4")

        for host in nm.all_hosts():
            for puerto in nm[host]['tcp']:
                if nm[host]['tcp'][puerto]['state'] == 'open':
                    servicio = nm[host]['tcp'][puerto]['name']
                    estado = nm[host]['tcp'][puerto]['state']
                    resultados.append(f"El puerto {puerto} está abierto. Utilizado por: {servicio} ({estado}).")

        self.informe_text.delete(1.0, tk.END)

        if resultados:
            self.informe_text.insert(tk.END, "\n".join(resultados))
        else:
            messagebox.showinfo("Información", "No se encontraron puertos abiertos.")

    def suspender_escaneo(self):
        # Lógica para suspender el escaneo (si es necesario)
        pass

    def limpiar_pantalla(self):
        self.informe_text.delete(1.0, tk.END)


# Crear una instancia de la aplicación y ejecutar el bucle de eventos
app = PortScannerApp()
app.ventana.mainloop()
