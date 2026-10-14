# OMEGA AI

**OMEGA AI** es un proyecto independiente de IA simbólica local para Python y Termux, orientado a funcionar sin root, offline y con poco almacenamiento.

> Estado: prototipo funcional en pruebas automatizadas. La compatibilidad real debe confirmarse en un dispositivo Termux/Android.

## Inicio rápido

Requiere Python 3.10 o posterior recomendado. Desde la carpeta del repositorio:

```bash
python -m py_compile omega_ai.py
python -m unittest -v test_omega
python omega_ai.py
```

En el prompt:

```text
ayuda
objetivo crear un experimento
pendientes
aprobar ID
```

Sustituye `ID` por el número mostrado. Antes de ejecutar una acción, OMEGA pide escribir exactamente `SI`. Revisa la operación antes de autorizarla.

## Validación manual en Termux

Consulta [`TERMUX_TESTING.md`](TERMUX_TESTING.md) para verificar paso a paso la aprobación individual, la auditoría local y la memoria persistente. La captura PCAPdroid se prueba por separado y requiere consentimiento VPN explícito de Android.

## Diseño

- Lenguaje declarativo propio; variables, comparaciones y acciones acotadas.
- Interfaz REPL minimalista inspirada en agentes de terminal: bienvenida compacta, prompt `❯`, acento naranja y comandos con prefijo `/` (por ejemplo, `/ayuda`). No usa dependencias de UI; los colores ANSI se desactivan fuera de una terminal interactiva o con `NO_COLOR`.
- Memoria persistente local SQLite e historial.
- Planificador simbólico y pequeño clasificador Naive Bayes implementado desde cero, entrenado solo con ejemplos locales que el usuario aprueba.
- Lista cerrada de operaciones aprobables: no ejecuta shell ni Python arbitrario.
- Límites de recursos para programas, memoria, historial, colas y tareas de laboratorio.
- NetMap para escaneos TCP conectando normalmente a IPs IPv4 privadas/loopback/link-local autorizadas.
- WireLab para inspección local de PCAP/PCAPNG.
- Captura opcional mediante PCAPdroid y consentimiento VPN de Android; duración y cantidad de paquetes son obligatoriamente limitadas (máximo 60 segundos/500 paquetes), incluso al usar el receptor independiente.

## Estructura

- `omega_ai.py` — núcleo de OMEGA y REPL.
- `test_omega.py` — pruebas unitarias del núcleo.
- `OMEGA.md` — documentación del lenguaje y seguridad.
- `OMEGA_PROGRESS.md` — bitácora de desarrollo y recuperación.
- `demo.omg` — programa demostrativo.
- `netmap.py`, `pcap_inspector.py`, `wirelab_live.py` — adaptadores ligeros para el laboratorio de red.

## Límites de seguridad

El escaneo y la captura son operaciones sensibles que solo deben usarse en dispositivos/redes propios o expresamente autorizados. La captura requiere configurar PCAPdroid y conceder el permiso VPN de Android. OMEGA reclama cada aprobación de forma atómica para evitar la doble ejecución accidental; si el proceso se interrumpe tras reclamarla, no se reintenta automáticamente. La aprobación local no protege frente a otro proceso con acceso a los archivos que manipule directamente la base de datos.

## Estado de pruebas

GitHub Actions compila el núcleo y ejecuta `test_omega.py`. Las pruebas automatizadas no sustituyen la validación en Android real. No se debe marcar como listo para producción hasta verificarlo en Termux.

## Independencia del proyecto

OMEGA se desarrolla en este repositorio, por separado de `herramientas-termux`. El historial anterior del prototipo queda conservado en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype.
