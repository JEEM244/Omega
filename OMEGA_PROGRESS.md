# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio oficial

- Proyecto independiente: https://github.com/JEEM244/Omega
- Rama de desarrollo: `main`.
- El prototipo histórico se conserva en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype; el PR histórico sigue sin fusionarse: https://github.com/JEEM244/herramientas-termux/pull/1
- El desarrollo de OMEGA continúa únicamente en este repositorio y no depende del lanzador del repositorio histórico.
- No declarar compatibilidad Android confirmada hasta probar en Termux en el dispositivo del usuario.
- Escaneo solo en objetivos autorizados; captura solo tras autorización explícita y consentimiento VPN de PCAPdroid.

## Estado del código

- `omega_ai.py`: núcleo OMEGA AI 0.3.0, lenguaje declarativo, variables/condiciones, planificación simbólica, memoria SQLite, historial, clasificador Naive Bayes local limitado y autorización por operación.
- Las aprobaciones ahora se reclaman mediante una actualización SQLite condicional antes de ejecutar efectos laterales; pruebas con dos conexiones verifican que una misma aprobación no se ejecute dos veces por una carrera.
- Si el proceso se interrumpe después de reclamar una aprobación, esta no se reintenta automáticamente. La autorización local no protege contra un proceso que manipule directamente los archivos o la base de datos.
- Se rechazan enlaces simbólicos para la base de datos, workspace y sidecars SQLite, incluido `-journal`.
- `pcap_inspector.py`: valida longitudes capturadas/originales, snaplen y fracciones de timestamp en PCAP; valida bloques y opciones PCAPNG, respeta la resolución de timestamp `if_tsresol` y reporta paquetes malformados en vez de omitirlos silenciosamente. El decodificador UDP rechaza longitudes inválidas o truncadas.
- `test_omega.py`: **83 pruebas automatizadas** que cubren lenguaje, memoria, autorización, carreras, enlaces simbólicos, NetMap, PCAP/PCAPNG, exportación de PCAPdroid y mensajes claros de aprobación.
- `netmap.py`: escáner TCP acotado para IPv4 privada/loopback/link-local.
- `wirelab_live.py`: receptor UDP en loopback para exportación PCAPdroid; ahora exige duración de 1–60 segundos y 1–500 paquetes, incluso si se ejecuta de forma independiente.
- `README.md`, `OMEGA.md`, `demo.omg` y `.github/workflows/omega-tests.yml` son parte del proyecto independiente.

## Validación CI

- Commit de código probado: `70ef0ce15b4122860c008036e1022f8c603a622b`.
- GitHub Actions run **38607607696**: `success`; compilación y **83 pruebas** completadas correctamente en Python **3.10, 3.11, 3.12 y 3.13**. La ejecución posterior validará también los cambios de documentación y `.gitignore`.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38607607696
- Se añadió una regresión que comprueba que el REPL explique que `ID` es un marcador y debe sustituirse por el número real, por ejemplo `aprobar 1`.
- `TERMUX_TESTING.md` documenta una secuencia manual por etapas para aprobación, auditoría y memoria persistente; la captura real queda separada.
- Esto no demuestra todavía el permiso VPN, la captura real, ni compatibilidad con todos los Android.

## Pendientes reales

1. Probar instalación limpia y funcionamiento en Termux en el Android del usuario; revisar errores y consumo de memoria/almacenamiento.
2. Verificar PCAPdroid de forma manual con consentimiento VPN, captura acotada y lectura posterior del archivo generado.
3. Seguir probando rutas, recuperación tras interrupciones, entradas malformadas y limitaciones del parser; no considerar que una auditoría puntual equivale a una auditoría de seguridad exhaustiva.
4. Tras recibir el resultado de Termux, corregir cualquier fallo reproducible y volver a ejecutar CI.

## Comandos para la prueba del dispositivo

```bash
git clone https://github.com/JEEM244/Omega.git
cd Omega
python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
python -m unittest -v test_omega
python omega_ai.py
```

En el REPL, comenzar con `ayuda`, `auditar` y operaciones locales sin efectos laterales. No probar captura hasta estar listo para autorizar PCAPdroid y el permiso VPN de Android.

## Recuperación

Antes de pausar, actualizar esta bitácora con el SHA real y la última validación de CI. No fusionar ni borrar el repositorio histórico. No afirmar que el proyecto está terminado antes de la validación real en Termux.
