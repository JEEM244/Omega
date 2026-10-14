# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio oficial

- Proyecto independiente: https://github.com/JEEM244/Omega
- Rama principal de desarrollo: `main`.
- El prototipo previo se conserva sin alterar en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype. El PR histórico permanece sin fusionar: https://github.com/JEEM244/herramientas-termux/pull/1
- El nuevo desarrollo se hace aquí, sin dependencia del lanzador del repositorio histórico.
- No declarar compatibilidad Android confirmada hasta probar en Termux en el dispositivo del usuario.
- Escaneo solamente en objetivos autorizados; captura solo tras autorización explícita y consentimiento VPN de PCAPdroid.

## Estado del código

- `omega_ai.py`: núcleo OMEGA AI 0.3.0, lenguaje declarativo, variables/condiciones, planificación simbólica, memoria SQLite, registro de eventos, clasificador Naive Bayes local limitado y autorización por operación.
- `test_omega.py`: suite independiente de **67 pruebas** para lenguaje, memoria, aprobación, NetMap, PCAP/PCAPNG y parser de PCAPdroid.
- `netmap.py`: escáner TCP connect de IPv4 privada/loopback/link-local; límites de puertos y timeout, con render compatible con el núcleo.
- `pcap_inspector.py`: analizador local PCAP/PCAPNG ligero.
- `wirelab_live.py`: receptor UDP loopback para exportación PCAPdroid, sin shell arbitrario.
- `README.md`, `OMEGA.md`, `demo.omg`.
- `.github/workflows/omega-tests.yml`: CI independiente.
- Se removió la dependencia de las pruebas al lanzador de `herramientas-termux`; el historial anterior sigue conservado.

## Última validación CI

- Commit con suite ampliada: `f62c0038f6e1ae580deffb3f2b210c7c6df9da53`.
- GitHub Actions run `38563258512`: `success`.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38563258512
- La compilación y la suite terminaron bien. Esto no prueba por sí mismo el permiso VPN, la captura real ni la compatibilidad con todos los Android.

## Siguiente trabajo

1. Revisar posibles fallos de seguridad en límites y rutas de SQLite, workspace y captura; corregir con pruebas específicas.
2. Revisar los límites/errores del parser PCAPNG, timestamps, paquetes truncados y tráfico UDP.
3. El usuario ejecuta en Termux:
   ```bash
   git clone https://github.com/JEEM244/Omega.git
   cd Omega
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
4. Analizar el resultado real del teléfono antes de considerar listo el proyecto.

## Recuperación

Antes de pausar, actualizar este archivo con SHA real y estado del run más reciente. No fusionar ni borrar el repositorio histórico.
