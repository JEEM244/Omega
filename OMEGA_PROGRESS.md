# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-15.

## Repositorio oficial

- Proyecto independiente: https://github.com/JEEM244/Omega
- Rama de desarrollo: `main`.
- El prototipo histórico se conserva en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype; el PR histórico sigue sin fusionarse: https://github.com/JEEM244/herramientas-termux/pull/1
- El desarrollo de OMEGA continúa únicamente en este repositorio y no depende del lanzador del repositorio histórico.
- `VISION.md` define la misión actual, los límites de lo que FORGE hace hoy y los criterios para aceptar nuevas funciones; usarlo como referencia antes de añadir módulos.
- No declarar compatibilidad Android confirmada hasta probar en Termux en el dispositivo del usuario.
- Escaneo solo en objetivos autorizados; captura solo tras autorización explícita y consentimiento VPN de PCAPdroid.

## Estado del código

- `omega_ai.py`: núcleo OMEGA AI 0.3.0, lenguaje declarativo, variables/condiciones, planificación simbólica, memoria SQLite, historial, clasificador Naive Bayes local limitado y autorización por operación.
- Interfaz de terminal añadida: bienvenida compacta inspirada en agentes CLI como Claude Code, prompt `❯`, acento naranja ANSI sin dependencias, etiquetas para errores/resultados y alias de comandos con `/` (por ejemplo, `/ayuda`). Respeta `NO_COLOR` y no añade interfaz web ni dependencias pesadas.
- La interfaz de terminal incluye bienvenida, degradación sin color, secuencias ANSI y alias `/` para comandos. OMEGA FORGE se añadió como módulo separado para comparar algoritmos y sintetizar expresiones aritméticas limitadas desde ejemplos.
- Las aprobaciones ahora se reclaman mediante una actualización SQLite condicional antes de ejecutar efectos laterales; pruebas con dos conexiones verifican que una misma aprobación no se ejecute dos veces por una carrera.
- Si el proceso se interrumpe después de reclamar una aprobación, esta no se reintenta automáticamente. La autorización local no protege contra un proceso que manipule directamente los archivos o la base de datos.
- Se rechazan enlaces simbólicos para la base de datos, workspace y sidecars SQLite, incluido `-journal`.
- `pcap_inspector.py`: valida longitudes capturadas/originales, snaplen y fracciones de timestamp en PCAP; valida bloques y opciones PCAPNG, respeta la resolución de timestamp `if_tsresol` y reporta paquetes malformados en vez de omitirlos silenciosamente. El decodificador UDP rechaza longitudes inválidas o truncadas.
- `test_omega.py`: la última CI confirmada ejecutó **124 pruebas** en cuatro versiones de Python. Las pruebas cubren núcleo, lenguaje, memoria, permisos, herramientas de red, síntesis de FORGE, guardado y reutilización de capacidades, y propuestas de evolución.
- `netmap.py`: escáner TCP acotado para IPv4 privada/loopback/link-local.
- `wirelab_live.py`: receptor UDP en loopback para exportación PCAPdroid; ahora exige duración de 1–60 segundos y 1–500 paquetes, incluso si se ejecuta de forma independiente.
- `omega_forge.py` (FORGE 0.2.0): intérprete de candidatos con gramática restringida, límites de tamaño, profundidad sintáctica, cantidad de nodos y pasos, comparador de algoritmos y sintetizador aritmético guiado por ejemplos. La síntesis explora fórmulas con hasta dos operaciones anidadas para entradas de 1 a 3 valores, agregados `sum`/`min`/`max`, constantes y operadores aritméticos, con máximo de 3000 candidatos y validación reservada; no ejecuta Python arbitrario. El manifiesto `forge_max_discovery.json` demuestra una síntesis reproducible de `max(xs)`.\n- FORGE puede serializar una función validada como capacidad JSON, guardar los casos de validación reservados y reutilizarla desde `workspace/` mediante el intérprete restringido. Cada ejecución vuelve a comprobar esos casos antes de aceptar datos nuevos. Guardar requiere encolar y aprobar una operación `file_create`; el candidato no puede importar módulos ni acceder a archivos o red. La evolución compara una versión existente contra una síntesis nueva usando ejemplos y validación; solo propone una nueva versión si la anterior falla o la nueva usa menos pasos estimados, nunca sobrescribe y conserva una nota de linaje.\n- La capacidad puede comprobarse con `/forja guardar forge_discovery.json suma.json`, aprobar el ID real con `SI`, revisar `/forja lista` y después ejecutar `/forja usar suma.json "[10, 5]"`. El catálogo solo reconoce formatos válidos y limita la inspección a 500 entradas.\n- `forge_demo.json` y `forge_discovery.json` son manifiestos reproducibles para comparar candidatos y descubrir expresiones.\n- `README.md`, `OMEGA.md`, `demo.omg` y `.github/workflows/omega-tests.yml` son parte del proyecto independiente.

## Validación CI

- Último commit validado por CI (incluye guía manual): `be103c5addefb0db75ff24d2845b814dfd74d783`.
- GitHub Actions run **38844518669**: `success`; compilación y **124 pruebas** completadas correctamente en Python **3.10, 3.11, 3.12 y 3.13**.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38844518669
- El rechazo concurrente usa una actualización SQLite condicional sobre `status='pending'`; la prueba de carrera confirma que aprobar y rechazar simultáneamente solo puede tener un ganador y que el estado coincide con el efecto ejecutado.
- WireLab Live intenta detener PCAPdroid desde `finally`, incluso si falla la recepción o escritura; una prueba simulada comprueba la llamada de detención sin iniciar una captura real.
- `TERMUX_TESTING.md` documenta una secuencia manual por etapas para aprobación, auditoría y memoria persistente; la captura real queda separada.
- Esto no demuestra todavía el permiso VPN, la captura real, ni compatibilidad con todos los Android.

## Validación manual de Termux (2026-10-14)

- OMEGA AI 0.3.0 inició en el Android del usuario desde Termux.
- Auditoría local autorizada: `SQLite integrity_check: ok`; workspace existe y es escribible; ejecución sin root; aproximadamente 25.45 GB libres; no consultó la red.
- Memoria persistente verificada: se guardó `prueba_persistencia = funciona_omega`, se leyó correctamente y se recuperó de nuevo después de cerrar y reiniciar OMEGA.
- Aprobación, rechazo individual e historial se probaron manualmente. Las solicitudes de auditoría antiguas se rechazaron y la cola quedó vacía.
- El usuario creó dos solicitudes de captura PCAPdroid (IDs locales 7 y 8), pero no autorizó ninguna; no se ha ejecutado una captura real. Se reservan para la última fase.
- La prueba manual del dispositivo corresponde al código anterior a los últimos commits de corrección; antes de cerrar el proyecto hay que sincronizar `main` en Termux y repetir compilación y todas las pruebas actuales.

## Pendientes reales

1. Continuar la revisión estática de entradas malformadas, límites de recursos y flujos de recuperación; la primera versión de FORGE crea y reutiliza capacidades aritméticas acotadas, pero todavía no modifica automáticamente el núcleo.
2. Sincronizar la versión final de `main` en Termux y ejecutar compilación y todas las pruebas actuales en el dispositivo.
3. Revisar la cola local y rechazar las solicitudes PCAPdroid antiguas que ya no se vayan a usar; no aprobarlas accidentalmente.
4. Dejar para el final la prueba real de PCAPdroid con consentimiento VPN, captura limitada y posterior inspección del archivo generado.
5. Corregir cualquier fallo reproducible y repetir CI antes de declarar una versión estable.

## Comandos para la prueba del dispositivo

```bash
git clone https://github.com/JEEM244/Omega.git
cd Omega
python -m py_compile omega_ai.py omega_forge.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
python -m unittest -v test_omega
python omega_ai.py
```

En el REPL, comenzar con `ayuda`, `auditar` y operaciones locales sin efectos laterales. No probar captura hasta estar listo para autorizar PCAPdroid y el permiso VPN de Android.

## Prueba manual OMEGA FORGE 0.2 en Termux

Esta fase no requiere PCAPdroid ni permisos VPN. En el teléfono, desde la carpeta del repositorio:

```bash
git pull
python -m py_compile omega_ai.py omega_forge.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
python -m unittest -v test_omega
python omega_forge.py --synthesize forge_max_discovery.json
python omega_ai.py
```

En la terminal interactiva, prueba en este orden:

```text
/forja descubrir forge_max_discovery.json
/forja guardar forge_max_discovery.json maximo.json
/pendientes
/aprobar ID_REAL
SI
/forja lista
/forja usar maximo.json "[9, 1, 5]"
/forja evolucionar forge_max_discovery.json maximo.json maximo_v2.json
```

Sustituye `ID_REAL` por el identificador que OMEGA muestre y confirma solo después de revisar la descripción. El resultado esperado al usar la capacidad es `9`. La última orden debería indicar que no se necesita una nueva versión si la capacidad guardada ya tiene el mismo resultado y el mismo coste estimado; no debería encolar un cambio. Esta prueba valida el ciclo local de FORGE, no la evolución automática del núcleo de OMEGA.

## Recuperación

Antes de pausar, actualizar esta bitácora con el SHA real y la última validación de CI. No fusionar ni borrar el repositorio histórico. No afirmar que el proyecto está terminado antes de la validación real en Termux.
