---
title: dOOMs Day
platform: Hack The Box Sherlocks
difficulty: Easy
focus: [purple-team, dfir, pcap, apache, php]
cves: [CVE-2026-109618, CVE-2026-109619]
date: 2026-11-12
---

# dOOMs Day — Análisis Purple Team y Reconstrucción Forense

> **Sherlock:** `dOOMs Day` (Hack The Box Sherlocks · Easy)  
> **Fecha de resolución:** `2026-11-12`  
> **Enfoque:** Purple Team (Defensivo / Ofensivo) · Análisis forense de red y logs (`PCAP` + `access.log` / `error.log`)  
> **CVEs involucrados:** `CVE-2026-109618` / `CVE-2026-109619`

---

## 1. Escenario y Alcance Forense

Investigación sobre un servidor interno de desarrollo comprometido ejecutando **PHP 8.4.26** sobre **Apache** en entorno contenedorizado bajo usuario sin privilegios (`www-data`).  
Toda la resolución se realizó **exclusivamente por análisis forense pasivo** (lectura y correlación de `Capture.pcap`, `access.log` y `error.log`), sin ejecutar ni reproducir el exploit contra ningún entorno.

### Stack de Análisis Utilizado
- **`tshark` (CLI):** filtrado de paquetes (`-T fields`), normalización temporal a UTC (`-t ud`), aislamiento de handshakes TCP (`SYN`/`SYN-ACK`) y reconstrucción de flujos en texto plano (`-z follow,tcp,ascii,<stream>`).
- **Herramientas UNIX de texto (`grep`, `sed`, `cut`, `sort`, `uniq`):** conteo de peticiones por PID de worker, extracción de tamaños de respuesta y cruce entre eventos de Apache/PHP y streams TCP.

---

## 2. Cómo se Resolvió (Metodología de Investigación)

1. **Normalización temporal UTC:** los logs de Apache/PHP registraban eventos en UTC mientras el cliente local operaba en otra zona horaria; forzar salida UTC en `tshark` permitió alinear con precisión el inicio del contacto en red con las primeras anomalías en logs.
2. **Aislamiento de patrones de saturación:** filtrando paquetes iniciales de conexión (`SYN` sin `ACK`) desde la IP de origen interna y cruzando `Content-Length` / boundaries en `error.log`, se identificó el agotamiento deliberado del pool de workers mediante subidas multipart retenidas (*stalled uploads*).
3. **Correlación por PID y ventanas de caída:** agrupando requests por PID de proceso Apache en rangos temporales se evidenció el *heap grooming* sobre un worker concreto y el reenganche rápido (<1s) cada vez que un worker terminaba abruptamente.
4. **Diferencial de bytes en fuga de memoria:** comparando el tamaño reportado de chunks `Set-Cookie` en `error.log` frente al `Content-Length` total en `access.log`, se aisló la porción exacta de memoria heap filtrada dentro de `PHPSESSID` (incluyendo un puntero de 64 bits en espacio de usuario x86-64).
5. **Detección del momento exacto de RCE por cadencia TCP:** observar el ritmo de intentos `SYN` salientes (reintentos con backoff mientras el listener estaba caído vs. handshake completo `SYN`/`SYN-ACK`/`ACK` en el stream activo) permitió fechar la obtención efectiva de shell remota y reconstruir la sesión post-explotación completa mediante `follow,tcp,ascii`.

---

## 3. Cadena Ataque ↔ Defensa (Purple Team)

| Fase | Vector Ofensivo Observado | Técnica Forense | Contraparte Defensiva / Hardening |
| :--- | :--- | :--- | :--- |
| **1. Reconocimiento** | Primer contacto anómalo contra el stack PHP/Apache desde host interno. | Correlación UTC entre `access.log`/`error.log` y `Capture.pcap`. | Sincronización NTP uniforme en toda la infraestructura + alertas WAF/IDS sobre patrones anómalos internos. |
| **2. Worker Pool Exhaustion** | Saturación de workers mediante *stalled multipart uploads* con campos numéricos secuenciales. | Filtro `SYN` por origen + inspección de `max_input_vars` y boundaries en `error.log`. | `Timeout` y `RequestReadTimeout` estrictos en Apache, límites por IP (`mod_qos`/`mod_evasive`) y alertas sobre `max_input_vars`. |
| **3. Heap Grooming** | Fijación repetida de requests en un mismo PID para moldear el heap antes de cada fallo. | Agrupación de peticiones por PID y tiempos de reinicio de worker. | Reducir `MaxRequestsPerChild` / aislar workers por contenedor y reforzar ASLR para acortar la ventana de reutilización. |
| **4. Cadena CVE → OOM RCE** | Encadenamiento de `CVE-2026-109618` y `CVE-2026-109619` forzando un Out-Of-Memory controlado (`memory_limit`). | Identificación de versión en `X-Powered-By` y warnings OOM previos al crash. | Parcheo inmediato de PHP, `memory_limit` conservador con alertas sostenidas y firmas WAF para la cadena conocida. |
| **5. Fuga Heap vía Cookie** | Exfiltración de memoria heap no inicializada en `PHPSESSID` exponiendo punteros x86-64. | Diferencial entre chunk `Set-Cookie` en `error.log` y `Content-Length` en `access.log`. | `zend.exception_ignore_args`, parche del CVE de fuga y bloqueo WAF ante cookies de sesión anómalamente largas. |
| **6. Shell Inversa Post-RCE** | Conexión TCP saliente desde el contenedor ejecutando shell interactiva sin PTY. | Reconstrucción completa del stream TCP saliente con `tshark -z follow,tcp,ascii`. | **Egress filtering** estricto en servidor web, detección IDS de shells no-HTTP, contenedores read-only y `cap_drop ALL`. |
| **7. Reconocimiento Interno** | Enumeración básica de kernel y procesos activos dentro del contenedor (`www-data`). | Lectura directa de comandos ejecutados dentro del flujo TCP reconstruido. | Reglas runtime (`Falco` / `auditd`) alertando procesos hijo inesperados (`sh`/`bash`) lanzados por `apache2`. |
| **8. Búsqueda de Datos** | Barrido recursivo de bases de datos locales (`.sqlite`, `.db`) en el sistema de archivos. | Auditoría del comando final en el stream TCP reconstruido. | Retirar archivos SQLite sensibles del alcance de `www-data`, usar gestores de secretos y alertar `find /` en cuentas de servicio. |

---

## 4. Lecciones Metodológicas Clave

- **Alineación temporal estricta:** sin normalizar zonas horarias a UTC en herramientas de red y logs, cualquier línea de tiempo forense se desfasará.
- **Métricas en bytes como señal analítica:** comparar tamaños entre capas (HTTP `Content-Length` vs. logs internos de depuración) separa contenido legítimo de memoria fugada.
- **Cadencia de handshakes TCP:** distinguir reintentos fallidos (`SYN` sin respuesta) de un `SYN-ACK` inmediato permite confirmar el instante exacto de ejecución remota sin depender únicamente de logs de aplicación.
- **Separación hecho vs. hipótesis:** contrastar cada inferencia con el stream reconstruido evita consolidar falsos positivos durante la investigación.

---

## 5. Mapeo MITRE ATT&CK

* **T1595.002** — Active Scanning: Vulnerability Scanning (reconocimiento inicial)
* **T1499.002** — Endpoint Denial of Service: Service Exhaustion Flood (agotamiento del pool de workers Apache)
* **T1190 / T1203** — Exploit Public-Facing Application (`CVE-2026-109618` / `CVE-2026-109619` OOM RCE en PHP)
* **T1005 / T1552.001** — Data from Local System / Credentials in Files (fuga de heap en `PHPSESSID` y búsqueda de SQLite local)
* **T1059.004 / T1071** — Command and Scripting Interpreter: Unix Shell / Application Layer Protocol (reverse shell saliente)
* **T1082 / T1083** — System Information Discovery / File and Directory Discovery (reconocimiento post-explotación)

---

## 6. IOCs y Señales Observables (SIEM / Red / Host)

* **Logs de Apache/PHP (`error.log`):** ráfagas de `Allowed memory size of ... bytes exhausted` o `child pid ... exit signal Segmentation fault (11)` correlacionadas con peticiones `POST` `multipart/form-data`.
* **Logs de acceso (`access.log`):** peticiones `multipart/form-data` con alta latencia o estado `408`/`500` previas a actividad saliente anómala, y cabeceras `Set-Cookie: PHPSESSID=` de longitud inusual.
* **Red (`PCAP` / IDS):** conexiones TCP salientes originadas desde el contenedor web hacia puertos no estándar con patrón de *backoff* en los reintentos de handshake.
* **Host / Contenedor (`auditd` / `Falco`):** eventos `execve` lanzando `/bin/sh`, `bash` o `find /` cuyo `ppid` pertenezca al proceso `apache2` / `php-fpm` (`www-data`).
