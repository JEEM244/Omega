# OMEGA AI

**OMEGA AI** es un proyecto independiente de IA simbólica local para Python y Termux, orientado a funcionar sin root, offline y con poco almacenamiento.

> Estado: prototipo funcional en pruebas automatizadas. La compatibilidad real debe confirmarse en un dispositivo Termux/Android.

## Inicio rápido

Requiere Python 3.10 o posterior recomendado. Desde la carpeta del repositorio:

```bash
python -m py_compile omega_ai.py omega_forge.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
python -m unittest -v test_omega
python omega_ai.py
```

En el prompt:

```text
ayuda
/forja
/objetivo crear un experimento
/pendientes
/aprobar ID
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
- `omega_forge.py` — laboratorio local de algoritmos, evaluación de candidatos y síntesis aritmética acotada.
- `test_omega.py` — pruebas unitarias del núcleo y FORGE.
- `OMEGA.md` — documentación del lenguaje y seguridad.
- `OMEGA_PROGRESS.md` — bitácora de desarrollo y recuperación.
- `demo.omg` — programa demostrativo.
- `forge_demo.json` — manifiesto reproducible para comparar algoritmos.
- `forge_discovery.json` — ejemplo guiado para sintetizar y validar una expresión nueva.
- `netmap.py`, `pcap_inspector.py`, `wirelab_live.py` — adaptadores ligeros para el laboratorio de red.

## OMEGA FORGE

En la terminal escribe:

```text
/forja
/forja sum
/forja max
/forja forge_demo.json
/forja descubrir forge_discovery.json
```

FORGE compara estrategias para sumar y encontrar máximos, o carga un manifiesto JSON con candidatos personalizados. También puede sintetizar una expresión aritmética pequeña a partir de ejemplos y comprobarla con un conjunto de validación separado:

```bash
python omega_forge.py --spec forge_demo.json
python omega_forge.py --synthesize forge_discovery.json
```

El evaluador interpreta un subconjunto pequeño de sintaxis estilo Python; no usa `eval`, `exec`, comandos de shell, imports del candidato ni acceso de los candidatos a archivos o red. El sintetizador explora una gramática acotada de expresiones numéricas con entradas de 1 a 3 valores, constantes, `abs`, `len` y operadores `+`, `-`, `*`, `//` y `%`. No es un generador de algoritmos arbitrarios.

Las pruebas deben cubrir ejemplos y una validación reservada. Que una expresión pase los datos entregados no garantiza corrección universal. La puntuación de FORGE usa pasos estimados del intérprete, no milisegundos ni medición de velocidad nativa. FORGE no modifica el núcleo: es una primera base verificable para experimentar antes de añadir evolución automática.

## Límites de seguridad

El escaneo y la captura son operaciones sensibles que solo deben usarse en dispositivos/redes propios o expresamente autorizados. La captura requiere configurar PCAPdroid y conceder el permiso VPN de Android. OMEGA reclama cada aprobación de forma atómica para evitar la doble ejecución accidental; si el proceso se interrumpe tras reclamarla, no se reintenta automáticamente. La aprobación local no protege frente a otro proceso con acceso a los archivos que manipule directamente la base de datos.

## Estado de pruebas

GitHub Actions compila el núcleo y ejecuta `test_omega.py`. Las pruebas automatizadas no sustituyen la validación en Android real. No se debe marcar como listo para producción hasta verificarlo en Termux.

## Independencia del proyecto

OMEGA se desarrolla en este repositorio, por separado de `herramientas-termux`. El historial anterior del prototipo queda conservado en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype.
