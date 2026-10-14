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
- `test_omega.py`: **82 pruebas automatizadas** que cubren lenguaje, memoria, autorización, carreras, enlaces simbólicos, NetMap, PCAP/PCAPNG y exportación de PCAPdroid.
- `netmap.py`: escáner TCP acotado para IPv4 privada/loopback/link-local.
- `wirelab_live.py`: receptor UDP en loopback para exportación PCAPdroid; ahora exige duración de 1–60 segundos y 1–500 paquetes, incluso si se ejecuta de forma independiente.
- `README.md`, `OMEGA.md`, `demo.omg` y `.github/workflows/omega-tests.yml` son parte del proyecto independiente.

## Validación CI

- Commit de código probado: `8a8c1bb70929e30d1453b3581d8720a0e4445113`.
- GitHub Actions run **38606125912**: `success`; compilación y **82 pruebas** completadas correctamente.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38606125912
- La documentación y la bitácora actualizadas también pasaron CI en run **38606276955**: https://github.com/JEEM244/Omega/actions/runs/38606276955.
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
