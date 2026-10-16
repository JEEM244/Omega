# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-15.

## Repositorio oficial

- Proyecto independiente: https://github.com/JEEM244/Omega
- Rama de desarrollo: `main`.
- El prototipo histórico se conserva en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype; el PR histórico sigue sin fusionarse: https://github.com/JEEM244/herramientas-termux/pull/1
- El desarrollo de OMEGA continúa únicamente en este repositorio y no depende del lanzador del repositorio histórico.
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
- `test_omega.py`: última CI confirmada ejecutó **110 pruebas**; se añadió una prueba adicional para síntesis con tres entradas y dos operaciones anidadas, por lo que la nueva revisión espera 111. Las pruebas cubren núcleo, lenguaje, memoria, permisos, herramientas de red y OMEGA FORGE.
- `netmap.py`: escáner TCP acotado para IPv4 privada/loopback/link-local.
- `wirelab_live.py`: receptor UDP en loopback para exportación PCAPdroid; ahora exige duración de 1–60 segundos y 1–500 paquetes, incluso si se ejecuta de forma independiente.
- `omega_forge.py`: intérprete de candidatos con gramática restringida, límites de tamaño y pasos, comparador de algoritmos y sintetizador aritmético guiado por ejemplos. La síntesis ahora explora fórmulas con hasta dos operaciones anidadas para entradas de 1 a 3 valores, además de expresiones atómicas y combinaciones simples. Mantiene un máximo de 3000 candidatos y validación reservada; no ejecuta código Python arbitrario ni modifica automáticamente el núcleo.\n- `forge_demo.json` y `forge_discovery.json` son manifiestos reproducibles para comparar candidatos y descubrir expresiones.\n- `README.md`, `OMEGA.md`, `demo.omg` y `.github/workflows/omega-tests.yml` son parte del proyecto independiente.

## Validación CI

- Último commit de código y pruebas validado: `2297c05f133b58814b53efd98f44b87b45641217`.
- GitHub Actions run **38633480702**: `success`; compilación y **85 pruebas** completadas correctamente en Python **3.10, 3.11, 3.12 y 3.13**.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38633480702
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

1. Completar la revisión estática de los flujos de error, recuperación tras interrupciones, entradas malformadas y límites de recursos; agregar pruebas si se detectan huecos concretos.
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

## Recuperación

Antes de pausar, actualizar esta bitácora con el SHA real y la última validación de CI. No fusionar ni borrar el repositorio histórico. No afirmar que el proyecto está terminado antes de la validación real en Termux.
