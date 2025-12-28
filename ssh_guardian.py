#!/usr/bin/python3
import os
import subprocess
import time
import re
from collections import deque

# =================================================================
# CONFIGURACIÓN OPERACIONAL
# =================================================================
LOG_AUTH = "/var/log/auth.log"
LOG_GUARDIAN = "/var/log/ssh_guardian.log"
THRESHOLD = 3                # Capa de Decisión: Intentos permitidos
WINDOW_SECONDS = 60          # Ventana de tiempo de correlación
WHITELIST = {"127.0.0.1"}    # IPs protegidas (Añade la tuya aquí)

# Estructura para almacenar timestamps de intentos por IP
# Formato: { "IP": deque([timestamp1, timestamp2...]) }
attempts_history = {}

def write_log(message):
    """Registro de auditoría persistente"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_GUARDIAN, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def block_ip(ip):
    """Capa de Aplicación: Inserción de regla DROP en Iptables"""
    try:
        # Inserta la regla en la posición #1 para máxima prioridad
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        write_log(f"!!! BLOQUEO EJECUTADO !!!: {ip}")
    except subprocess.CalledProcessError as e:
        write_log(f"Error al ejecutar iptables para {ip}: {e}")

def process_line(line):
    """Motor de Correlación: Identificación de patrones de intrusión"""
    # Patrón para intentos fallidos estándar y usuarios inválidos
    if "Failed password" in line or "Invalid user" in line:
        ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        
        if ip_match:
            ip = ip_match.group(1)
            
            if ip in WHITELIST:
                return

            now = time.time()
            
            # Inicializar historial de la IP si no existe
            if ip not in attempts_history:
                attempts_history[ip] = deque()
            
            # Añadir el intento actual
            attempts_history[ip].append(now)
            
            # Limpiar intentos fuera de la ventana de tiempo (Capa de Decisión)
            while attempts_history[ip] and attempts_history[ip][0] < now - WINDOW_SECONDS:
                attempts_history[ip].popleft()
            
            count = len(attempts_history[ip])
            write_log(f"Intento detectado de {ip}. Total en {WINDOW_SECONDS}s: {count}")
            
            # Evaluar umbral de bloqueo
            if count >= THRESHOLD:
                block_ip(ip)
                # Limpiar historial tras bloqueo para evitar re-ejecución innecesaria
                del attempts_history[ip]

def monitor():
    """Ingesta de Datos: Monitoreo pasivo (Tail-style)"""
    write_log("Monitor activo. Esperando ataques...")
    
    # Abrir archivo y mover puntero al final para evitar procesar logs antiguos
    with open(LOG_AUTH, "r") as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Reducción de carga de CPU
                continue
            process_line(line)

if __name__ == "__main__":
    # Verificación de privilegios
    if os.getuid() != 0:
        print("Error: Este script debe ejecutarse como root (sudo).")
        exit(1)
    
    try:
        monitor()
    except KeyboardInterrupt:
        write_log("Monitor detenido manualmente.")
