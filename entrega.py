import os
import socket
import paramiko
import win32evtlog
import dns
import dns.resolver
server = "localhost"
logtype = "Security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

domains = {}
subs = "C:\\Python\\Python312\\Pys\\dns_search.txt"

res = dns.resolver.Resolver()
res.nameservers = ["8.8.8.8"]
res.port = 53

domain = "google.com" #valor por defecto. Despues se modifica
nums = True

def SSHLogin(host,port,username,password):
        try: 
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host,port=port,username=username,password=password)
            ssh_session = ssh.get_transport().open_session()
            if ssh_session.active:
                print("Inicio de sesión SSH exitoso en %s:%s con nombre de usuario %s y contraseña %s" % (host, port, username, password))
            ssh.close()
        except:
                print("SSH login failed %s %s" % (username,password))
        
        host = "127.0.0.1"
        sshport = 22
        with open("C:\\Python\\Python312\\Pys\\defaults.txt","r") as f:
            for line in f:
                vals = line.split()
                username = vals[0].strip()
                password = vals[1].strip()
                SSHLogin(host,sshport,username,password)


def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]]+result[1]
    except socket.herror:
        return []

def DNSRequest(domain):
    ips = []
    try:
        result = res.resolve(domain)
        if result:
            addresses = [a.to_text() for a in result]
            if domain in domains:
                domains[domain] = list(set(domains[domain]+addresses))
            else:
                domains[domain] = addresses
            for a in addresses:
                rd = ReverseDNS(a)
                for d in rd:
                    if d not in domains:
                        domains[d] = [a]
                        DNSRequest(d)
                    else:
                        domains[d] = [a]
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    return ips

def HostSearch(domain, dictionary, nums):
    successes = []
    for word in dictionary:
        d = word + "." + domain
        DNSRequest(d)
        if nums:
            for i in range(0, 10):
                s = word + str(i) + "." + domain
                DNSRequest(s)

dictionary = []
with open(subs, "r") as f:
    dictionary = f.read().splitlines()


def dnsexplorer():
    domain = input("Entre Dominio que desea escanear: ")
    ip_address = input("Entre la direccion IP que quiera escanear: ")
    res.nameservers = [ip_address]

    HostSearch(domain, dictionary, nums)
    for domain in domains:
        print("%s: %s" % (domain, domains[domain]))

def QueryEventLog(eventID):
    logs = []
    h = win32evtlog.OpenEventLog(server,logtype)
    while True:
        events = win32evtlog.ReadEventLog(h,flags,0)
        if events:
            for event in events:
                if event.EventID == eventID:
                    logs.append(event)
        else:
            break
    return logs

def DetectBruteForce():
    failures = {}
    events = QueryEventLog(4625)
    for event in events:
        account = event.StringInserts[5]
        if account in failures:
            failures[account] += 1
        else:
            failures[account] = 1
    for account in failures:
        print("%s: %s inicios de sesion fallidos:" % (account,failures[account]))

def CheckDefaultAccounts():
    with open("C:\\Python\\Python312\\Pys\\defaults.txt","r") as f:
        defaults = [[x for x in line.split(' ')][0] for line in f]
    with open("C:\\Python\\Python312\\Pys\\allowlist.txt","r") as f:
        allowed = f.read().splitlines()

    events = QueryEventLog(4624)
    for event in events:
        if event.StringInserts[8] == ["10","3"]:    
            if event.StringInserts[5] in defaults:
                if event.StringInserts[18] not in allowed:
                    print("Inicio de session no autorizado a %s desde %s" % (event.StringInserts[5],event.StringInserts[18]))

def port_scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) 
        sock.connect((host, port))
        print(f"Puerto {port} esta abierto")
        sock.close()
    except (socket.timeout, ConnectionRefusedError):
        print(f"Puerto {port} esta cerrado")

def buscar_puertos_inputs():
    target_host = input("Introduce el host que deseas escanear: ")

    target_ports = []

    print("Introduce los puertos a escanear. Escribe 'done' para finalizar.")
    while True:
        port_input = input("Puerto: ")
        if port_input.lower() == 'done':
            break
        else:
            try:
                port = int(port_input)
                target_ports.append(port)
            except ValueError:
                print("Por favor, introduce un número de puerto válido.")

    for port in target_ports:
        port_scan(target_host, port)

def analisis_traffic_log():

    log_file = "C:\\Python\\Python312\\Pys\\traffic_log.txt"
    source_ip = set()
    destination_ip = set()
    destination_port = set()
    protocol = set()
    timestamp = set()

    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split(",")
            if len(parts) >= 5:
                source_ip.add(parts[0])
                destination_ip.add(parts[1])
                destination_port.add(parts[2])
                protocol.add(parts[3])
                timestamp.add(parts[4])
    print("Source IP:")
    for ip in source_ip:
        print(ip)

    print("Destination IP:")
    for ip in destination_ip:
        print(ip)

    print("Destination Port:")
    for port in destination_port:
        print(port)

    print("Protocol:")
    for protocol in protocol:
        print(protocol)
    print("Timestamp:")
    for time in timestamp:
        print(time) 

def validar_credenciales_ssh():
   SSHLogin()

def Escanear_Logins():
    DetectBruteForce()
    CheckDefaultAccounts()

def escanear_puertos():

    target_host = input("Introduce el host que deseas escanear: ")

    cota_superior = int(input("Introduce cota superior de búsqueda: ")) 

    for port in range(1, cota_superior): 
        port_scan(target_host, port) 

def buscar_dns():
    dnsexplorer()


def validar_float(texto):
    while True:
        try:
            entrada=float(input(texto))
            return entrada
        except ValueError:
            print("Inserte un valor correcto")

def validar_int(texto):
    while True:
        try:
            entrada=int(input(texto))
            return entrada
        except ValueError:
            print("Inserte un valor correcto")
        
continuar = True
while continuar:    
    print('Inserte la operacion que desee')
    print("1) Sumar")
    print("2) Restar")
    print("3) Multiplicar")
    print("4) Dividir")
    print("5) Convertir de Farenheit a Celsius")
    print("6) Notacion cientifica de un numero")
    print("7) Conversion de Tiempo")
    print("8. Escaneo de puertos")
    print("9. Búsqueda de nombres de dominio DNS")
    print("10. Búsqueda de claves contra un servidor SSH")
    print("11. Análisis de Traffic Log")
    print("12. Detección de Inicios de sesion del Registro de Eventos.")
    print("13. Escaneo de puertos por rango")
    print("0. Salir")
    
    opcion= validar_int("Su opcion: ")
    if opcion <= 0 or opcion >= 13:
        print("Por favor, ingrese una opción válida (1-15).")
        continue
    if opcion>=1 and opcion<=4:        
        num1= validar_float("Inserte el primer numero: ")     
        num2=validar_float("Inserte el segundo numero: ")
    match opcion:
        case 1:
            print("Resultado: ",num1+num2)
        case 2:
            print("Resultado: ",num1-num2)
        case 3:
            print("Resultado: ",num1*num2)
        case 4:
            print("Resultado: ",num1/num2)
        case 5:            
            faren= validar_float("Inserte la tempreatura en farenheit: ")
            cels= 5/9*(faren-32)
            print(cels, "Celsios")
        case 6:            
            num= validar_float("Inserte el numero a convertir: ")
            ns= "{:.2e}".format(num)
            print("Numero Cientifico: ", ns)
        case 7: 
            seg_minuto =60
            seg_hora = 60*seg_minuto          
            seg=validar_float("Inserte los segundos a convertir: ")
            hora= seg//seg_hora
            seg= seg%seg_hora
            minutos=seg//seg_minuto
            seg=seg%seg_minuto

            print(hora, end='')
            if hora == 1:
                print(" hora ", end='')
            else:
                print(" horas ", end='')
            print(minutos, end='')
            if minutos == 1:
                print(" minuto ", end='')
            else:
                print(" minutos ", end='')
            print(seg, end='')
            if seg == 1:
                print(" segundo")
            else:
                print(" segundos")
        case 8:
            buscar_puertos_inputs()
        case 9:
            buscar_dns()
        case 10:
            validar_credenciales_ssh()
        case 11:
            analisis_traffic_log()
        case 12:
            Escanear_Logins()
        case 13:
            escanear_puertos()
        case 0:
            print("Saliendo del programa...")
            break

    input("Presione Enter Para Continuar")
    os.system('cls' if os.name == 'nt' else 'clear')







