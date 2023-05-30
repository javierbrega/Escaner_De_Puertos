import tkinter as tk  # Importar la biblioteca Tkinter para la interfaz gráfica
import nmap  # Importar la biblioteca nmap para el escaneo de puertos


def escanear_puertos():
    # Obtener la dirección IP ingresada por el usuario
    direccion_ip = ip_entry.get()

    # Obtener el número de puerto inicial ingresado por el usuario y convertirlo a entero
    puerto_inicial = int(puerto_inicial_entry.get())

    # Obtener el número de puerto final ingresado por el usuario y convertirlo a entero
    puerto_final = int(puerto_final_entry.get())

    resultados = []  # Lista para almacenar los resultados del escaneo de puertos

    nm = nmap.PortScanner()  # Crear una instancia de la clase PortScanner de nmap

    # Definir el rango de puertos a escanear
    scan_range = f"{puerto_inicial}-{puerto_final}"

    # Realizar el escaneo de puertos utilizando nmap
    nm.scan(direccion_ip, arguments=f"-p {scan_range} -T4")

    # Iterar sobre los hosts encontrados en el escaneo
    for host in nm.all_hosts():
        # Iterar sobre los puertos encontrados para cada host
        for puerto in nm[host]['tcp']:
            # Verificar si el puerto está abierto
            if nm[host]['tcp'][puerto]['state'] == 'open':
                resultados.append(f"El puerto {puerto} está abierto.")

    # Borrar el contenido existente en el área de texto
    informe_text.delete(1.0, tk.END)

    # Insertar los resultados del escaneo en el área de texto
    informe_text.insert(tk.END, "\n".join(resultados))


# Crear la ventana principal
ventana = tk.Tk()

ventana.title("Escaneo de Puertos")  # Establecer el título de la ventana

# Etiquetas y campos de entrada para la dirección IP y los puertos inicial y final
ip_label = tk.Label(ventana, text="Dirección IP:")
ip_label.pack()
ip_entry = tk.Entry(ventana)
ip_entry.pack()

puerto_inicial_label = tk.Label(ventana, text="Puerto Inicial:")
puerto_inicial_label.pack()
puerto_inicial_entry = tk.Entry(ventana)
puerto_inicial_entry.pack()

puerto_final_label = tk.Label(ventana, text="Puerto Final:")
puerto_final_label.pack()
puerto_final_entry = tk.Entry(ventana)
puerto_final_entry.pack()

# Botón para iniciar el escaneo de puertos
escanear_button = tk.Button(ventana, text="Escanear", command=escanear_puertos)
escanear_button.pack()

# Área de texto para mostrar el informe del escaneo
informe_text = tk.Text(ventana, height=10, width=50)
informe_text.pack()

ventana.mainloop()  # Iniciar el bucle de eventos de la ventana
