# OMEGA AI — prototipo para Termux

OMEGA AI es un agente simbólico local y experimental. La versión 0.3.0 combina un planificador por reglas explícitas, un lenguaje declarativo propio, una cola de aprobación y memoria SQLite. No es un modelo lingüístico avanzado. No requiere root ni dependencias Python externas; el núcleo funciona offline.

## Requisitos

- Termux actualizado.
- Python 3.10 o posterior recomendado.
- No requiere root, Nmap, conexión a Internet ni paquetes adicionales de Python.

## Inicio

Desde la carpeta del repositorio:

    python omega_ai.py

Los datos se guardan en ~/.omega_ai/, con memoria en omega.sqlite3 y archivos generados en workspace/. Para probar con otro directorio:

    python omega_ai.py --home "$HOME/omega-test"

## Primer experimento

En la terminal escribe `/forja` para ejecutar el laboratorio puro de FORGE, o prueba el flujo de objetivo:

    /objetivo crear un experimento
    pendientes
    aprobar 1
    auditar
    historial

OMEGA mostrará la operación y pedirá escribir exactamente SI antes de ejecutarla. Aprueba los pasos siguientes uno por uno. No se ejecuta ninguna acción al planificar ni al cargar un programa.

## Lenguaje OMEGA 0.3

El repositorio incluye demo.omg. Desde la carpeta del repositorio, escribe:

    lenguaje demo.omg
    pendientes

El compilador comprueba el programa y encola las acciones ejecutables. Cada acción necesita aprobación individual. Las definiciones de variables y la evaluación de condiciones son pasos puros de compilación: no modifican archivos, memoria ni el sistema.

### Instrucciones

- DEFINIR nombre = "texto" — define una variable de texto inmutable.
- DEFINIR numero = 42 — define una variable numérica inmutable.
- MOSTRAR "texto" — propone mostrar texto tras aprobación.
- MOSTRAR $nombre — propone mostrar el valor de una variable.
- MOSTRAR "Hola $nombre" — permite interpolar variables en texto.
- SUMAR 20 22 o SUMAR $a $b — propone un cálculo.
- SI $a < $b ENTONCES MOSTRAR "verdadero" — evalúa una condición y, si es cierta, encola una única acción.
- ESTADO — propone consultar el estado local.
- AUDITAR — propone revisar integridad SQLite, permisos del workspace, espacio libre y cola pendiente; no consulta la red.
- COMPACTAR — propone truncar el WAL y ejecutar VACUUM en SQLite; requiere aprobación y suficiente espacio libre.
- ESCANEAR "192.168.1.10" PUERTOS "22,80" AUTORIZADO — propone un escaneo TCP con NetMap; solo IPv4 privada, loopback o link-local, máximo 100 puertos y aprobación individual.
- INSPECCIONAR "~/captura.pcap" — propone analizar una captura local con WireLab; requiere aprobación, ruta dentro del directorio personal, archivo regular no enlazado y máximo 50 MiB/100 paquetes.
- CAPTURAR 10 SEGUNDOS MAX 100 PAQUETES — propone iniciar PCAPdroid durante un máximo de 60 segundos y 500 paquetes; requiere aprobación, puede solicitar permiso VPN de Android y guarda la captura en el directorio personal.
- historial [N] — muestra las últimas operaciones en modo de solo lectura (1 a 100 registros).
- aprender "frase" = intención — propone añadir un ejemplo etiquetado al clasificador local; requiere aprobación.
- RECORDAR "clave" = "valor" — propone guardar una memoria persistente.
- LEER_MEMORIA "clave" — propone leer una memoria.
- CREAR "archivo.txt" = "contenido" — propone crear un archivo nuevo.

Operadores de condición: ==, !=, >, <, >= y <=. Ambos lados deben ser del mismo tipo. Las variables no se pueden redefinir dentro del mismo programa. No se admiten bucles, funciones de usuario ni condiciones anidadas en esta versión.

La captura OMEGA se apoya en wirelab_live.py, requiere PCAPdroid y puede activar la solicitud de permiso VPN de Android; se limita a 60 segundos/500 paquetes y no sobrescribe archivos. El receptor independiente también exige límites explícitos de 1–60 segundos y 1–500 paquetes, para evitar capturas ilimitadas por omisión. Aprueba solo si deseas capturar el tráfico de tu dispositivo.

La inspección OMEGA se apoya en pcap_inspector.py y solo lee archivos PCAP/PCAPNG dentro del directorio personal; procesa como máximo 100 paquetes de archivos de hasta 50 MiB y requiere aprobación. El escaneo OMEGA se apoya en netmap.py, usa TCP connect sin root, solo acepta IPv4 privada/loopback/link-local y limita el lote a 100 puertos; el usuario debe indicar AUTORIZADO y después confirmar SI para ejecutar. El comando compactar solicita aprobación antes de reducir el almacenamiento de SQLite; si no hay al menos 1 MiB libre o el doble del tamaño de la base, se niega a ejecutar VACUUM. Los archivos solo se crean dentro de ~/.omega_ai/workspace, con nombres simples y sin sobrescribir archivos existentes. OMEGA rechaza workspace, base de datos y archivos auxiliares WAL/SHM/journal cuando son enlaces simbólicos, limita el tamaño del texto tras interpolar variables y limita cada programa a 100 líneas/instrucciones significativas. No hay evaluación de Python, ejecución de shell ni escritura en rutas arbitrarias.

## OMEGA FORGE 0.2

FORGE es el primer experimento de OMEGA dedicado a generar y evaluar soluciones pequeñas. En la terminal:

    /forja
    /forja sum
    /forja max
    /forja forge_demo.json
    /forja descubrir forge_discovery.json

Desde la línea de comandos se puede ejecutar de la misma forma:

    python omega_forge.py
    python omega_forge.py --spec forge_demo.json
    python omega_forge.py --synthesize forge_discovery.json

### Comparación de candidatos

Los manifiestos de tipo `--spec` contienen exactamente `name`, `cases` y `candidates`. Cada caso tiene `input` y `expected`; cada candidato tiene `name` y código en `source`, con una única función `def solve(datos):`. FORGE comprueba todos los candidatos antes de ejecutar la suite y solo interpreta una gramática restringida.

### Síntesis desde ejemplos

Los manifiestos de tipo `--synthesize` contienen exactamente `name`, `examples` y `validation`. Cada ejemplo y caso de validación tiene una lista numérica `input` y una salida numérica (`output`). Debe haber entre 3 y 20 ejemplos y entre 1 y 20 casos reservados, con una aridad uniforme de 1 a 3 números.

El sintetizador explora expresiones cortas construidas con entradas, constantes, `abs`, `len` y los operadores `+`, `-`, `*`, `//` y `%`. Elige la expresión más sencilla que coincida tanto con los ejemplos como con la validación. Es síntesis acotada de expresiones, no generación de programas arbitrarios; si no encuentra una expresión válida, informa que no pudo resolver el conjunto.

El intérprete no permite imports de candidatos, llamadas fuera de una lista cerrada, atributos, acceso a archivos, red, shell, `eval` ni `exec`. Limita el código fuente, las colecciones, la profundidad, las iteraciones y los pasos. El manifiesto JSON seleccionado por el usuario se lee como archivo normal, sin seguir enlaces simbólicos.

El puntaje por pasos es una estimación del trabajo dentro del intérprete, no milisegundos ni una medición de rendimiento nativo. Validar contra ejemplos suministrados no demuestra corrección universal. FORGE no reescribe aún el núcleo de OMEGA: es el primer mecanismo verificable para generar alternativas pequeñas y comparar si explican los datos.

## OMEGA FORGE: guardar y reutilizar capacidades

FORGE puede sintetizar una expresión aritmética desde ejemplos y validarla con casos reservados. Para guardar una capacidad validada dentro de `~/.omega_ai/workspace`, usa:

```text
/forja guardar forge_discovery.json suma.json
/pendientes
/aprobar ID_REAL
```

Revisa la descripción de la operación y confirma con `SI` únicamente si el archivo propuesto es el esperado. El archivo es un manifiesto JSON con código fuente de una función restringida, no un módulo Python ejecutable.

Para reutilizarlo, proporciona datos JSON explícitos:

```text
/forja usar suma.json "[10, 5]"
```

FORGE ejecuta la función mediante su intérprete limitado, con restricciones de tamaño, profundidad, colección y pasos. Rechaza rutas fuera de `workspace`, enlaces simbólicos, formatos desconocidos y sintaxis no permitida. La validación con ejemplos no demuestra corrección universal; trata cada capacidad como experimental.

## Seguridad y límites

- El planificador es una demostración transparente basada en reglas, no un LLM ni inteligencia general.
- Las operaciones propuestas se guardan en SQLite y requieren autorización explícita en la interfaz interactiva.
- El método interno de ejecución exige una confirmación explícita de aprobación; el REPL además pide escribir exactamente SI. El historial es una consulta de solo lectura.
- Solo hay un conjunto cerrado de tipos de acción permitidos.
- La memoria persistente por sí sola no equivale a aprendizaje. OMEGA 0.3 incorpora un clasificador de intención Naive Bayes multinomial pequeño, entrenado desde cero con ejemplos locales aprobados. No descarga modelos ni consulta servicios externos. Requiere ejemplos de al menos dos intenciones distintas; con menos datos el planificador usa sus reglas transparentes. El aprendizaje es limitado y no equivale a inteligencia general.
- Cada aprobación se reclama con una actualización SQLite condicional antes de cualquier efecto lateral, evitando ejecutar dos veces la misma operación por carreras entre procesos. Si el proceso se interrumpe después de reclamarla, no se reintenta automáticamente. La aprobación local no protege frente a otro proceso con acceso a los archivos que manipule directamente la base de datos.

## Aprendizaje local

Ejemplo: escribe aprender "quiero revisar el estado del sistema" = diagnostico, después consulta pendientes y aprueba el identificador de la operación. Repite con otra intención, por ejemplo aprender "quiero guardar un recuerdo" = memoria. Desde entonces, objetivo puede utilizar esos ejemplos para clasificar nuevas frases. Cada alta de ejemplo requiere aprobación y se guardan como máximo 1000 ejemplos. La memoria mantiene hasta 500 claves, el historial de eventos 2000 entradas, las operaciones finalizadas 2000 registros y la cola hasta 100 operaciones pendientes (las pendientes no se eliminan automáticamente).

Intenciones permitidas: experimento, memoria, diagnostico y general. El clasificador usa solo Python estándar, tokenización sencilla y suavizado de Laplace; no descarga ni ejecuta código de los ejemplos.

## Pruebas

    python -m py_compile omega_ai.py omega_forge.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
    python -m unittest -v test_omega
    python -m unittest -v

La integración en Termux debe verificarse en el dispositivo Android real. Las pruebas unitarias no demuestran compatibilidad con todos los fabricantes o versiones de Android.
