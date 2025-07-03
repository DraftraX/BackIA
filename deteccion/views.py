import os
import re
import psutil
import subprocess
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from collections import deque

# Configuración de Snort
SNORT_PATH = r"C:\Snort\bin\snort.exe"
SNORT_CONF = r"C:\Snort\etc\snort.conf"
LOG_DIR = r"C:\Snort\log"
INTERFACE_ID = "5"

class IniciarSnortAPIView(APIView):
    def get(self, request):
        if self.is_snort_running():
            return Response({"status": "Snort ya está en ejecución."}, status=status.HTTP_200_OK)

        try:
            self.launch_snort()
            return Response({"status": "Snort iniciado correctamente."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def is_snort_running(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and 'snort.exe' in proc.info['name'].lower():
                return True
        return False

    def launch_snort(self):
        command = [
            SNORT_PATH,
            "-A", "fast",
            "-c", SNORT_CONF,
            "-i", INTERFACE_ID,
            "-l", LOG_DIR
        ]
        subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)

class SnortLogAPIView(APIView):
    def get(self, request):
        alerts = []
        alert_file = os.path.join(LOG_DIR, "alert.ids")

        if not os.path.exists(alert_file):
            return Response({"error": "El archivo alert.ids no existe."}, status=404)

        try:
            with open(alert_file, "r", encoding="latin1") as f:
                lines = deque(f, maxlen=200)  # Últimas 200 líneas para mantenerlo rápido
        except Exception as e:
            print(f"[ERROR] No se pudo leer alert.ids: {e}")
            return Response({"error": str(e)}, status=500)

        for line in lines:
            line = line.strip()

            # Filtro amplio: cualquier línea que contenga [SCAN] o (portscan)
            if "[SCAN]" in line or "(portscan)" in line:
                try:
                    timestamp = line.split()[0]
                    msg_match = re.search(r"\[\*\*\] \[\d+:\d+:\d+\] (.*?) \[\*\*\]", line)
                    class_match = re.search(r"\[Classification: (.*?)\]", line)
                    prio_match = re.search(r"\[Priority: (\d+)\]", line)
                    proto_match = re.search(r"\{(.*?)\}", line)
                    ip_match = re.search(r"([\d:.a-fA-F]+):?(\d+)? -> ([\d:.a-fA-F]+):?(\d+)?", line)

                    if msg_match and prio_match and proto_match and ip_match:
                        src_ip = ip_match.group(1)
                        src_port = ip_match.group(2)
                        dst_ip = ip_match.group(3)
                        dst_port = ip_match.group(4)

                        def detect_ip_version(ip):
                            return "IPv4" if '.' in ip else "IPv6"

                        alerts.append({
                            "message": msg_match.group(1),
                            "classification": class_match.group(1) if class_match else "N/A",
                            "priority": int(prio_match.group(1)),
                            "timestamp": timestamp,
                            "src_ip": src_ip,
                            "src_port": int(src_port) if src_port else None,
                            "dst_ip": dst_ip,
                            "dst_port": int(dst_port) if dst_port else None,
                            "protocol": proto_match.group(1),
                            "ip_version": detect_ip_version(src_ip),
                            "logfile": "alert.ids"
                        })
                except Exception as e:
                    print(f"[ERROR] Línea malformada: {e}")

        print(f"[INFO] Total de alertas SCAN (últimas 200 líneas): {len(alerts)}")
        return Response(alerts, status=status.HTTP_200_OK)
