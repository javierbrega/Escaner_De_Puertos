import tkinter as tk
import nmap
from tkinter import ttk
from threading import Thread


class PortScannerApp:
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.title("Escaneo de Puertos -  By Javier Brega")
        self.ventana.configure(bg='white')  # Establecer el color de fondo de la ventana

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

        self.button_frame = tk.Frame(self.ventana, bg='white')  # Establecer el color de fondo del frame
        self.button_frame.pack()

        self.escanear_button = tk.Button(self.button_frame, text="Escanear", command=self.escanear_puertos,
                                         bg='lightblue', fg='black')  # Establecer colores de fondo y primer plano
        self.escanear_button.pack(side=tk.LEFT, padx=5, pady=5)  # Agregar espacio entre los botones

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

        self.informe_text = tk.Text(self.ventana, height=10, width=50)
        self.informe_text.pack()

        self.nm = nmap.PortScanner()
        self.hilo_escaneo = None

    # Resto del código...

    def escanear_puertos(self):
        self.limpiar_pantalla()

        direccion_ip = self.ip_entry.get()
        puerto_inicial = int(self.puerto_inicial_entry.get())
        puerto_final = int(self.puerto_final_entry.get())

        self.escanear_button.config(state=tk.DISABLED)
        self.suspender_button.config(state=tk.NORMAL)
        self.limpiar_button.config(state=tk.DISABLED)

        self.hilo_escaneo = Thread(target=self.realizar_escaneo, args=(direccion_ip, puerto_inicial, puerto_final))
        self.hilo_escaneo.start()

    def realizar_escaneo(self, direccion_ip, puerto_inicial, puerto_final):
        scan_range = f"{puerto_inicial}-{puerto_final}"
        self.nm.scan(direccion_ip, arguments=f"-p {scan_range} -T4")

        resultados = []
        total_puertos = puerto_final - puerto_inicial + 1
        progreso_actual = 0

        for host in self.nm.all_hosts():
            for puerto in self.nm[host]['tcp']:
                if self.hilo_escaneo.is_alive() == False:
                    self.limpiar_pantalla()
                    return

                if self.nm[host]['tcp'][puerto]['state'] == 'open':
                    resultados.append(f"El puerto {puerto} está abierto.")

                progreso_actual += 1
                porcentaje = (progreso_actual / total_puertos) * 100
                self.progreso["value"] = porcentaje
                self.progreso.update()

        self.informe_text.delete(1.0, tk.END)
        self.informe_text.insert(tk.END, "\n".join(resultados))

        self.escanear_button.config(state=tk.NORMAL)
        self.suspender_button.config(state=tk.DISABLED)
        self.limpiar_button.config(state=tk.NORMAL)

    def suspender_escaneo(self):
        if self.hilo_escaneo and self.hilo_escaneo.is_alive():
            self.hilo_escaneo.join()

    def limpiar_pantalla(self):
        self.informe_text.delete(1.0, tk.END)
        self.progreso["value"] = 0

    def iniciar_aplicacion(self):
        self.ventana.mainloop()


if __name__ == "__main__":
    app = PortScannerApp()
    app.iniciar_aplicacion()
