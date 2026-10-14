# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio oficial y reglas

- Repositorio independiente: https://github.com/JEEM244/Omega
- Rama de trabajo: `main`.
- Se conserva el prototipo anterior intacto en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype; el PR histórico permanece sin fusionar: https://github.com/JEEM244/herramientas-termux/pull/1
- El desarrollo nuevo se realiza en este repositorio, sin depender del lanzador de herramientas-termux.
- No asegurar compatibilidad Android hasta probar el proyecto desde Termux real.
- Escaneo solo en objetivos autorizados. Captura solo con autorización y aceptación de la VPN de PCAPdroid.

## Código actual

- `omega_ai.py`: OMEGA AI 0.3.0, lenguaje declarativo, variables/condiciones, planificador simbólico, memoria SQLite, aprendizaje local limitado y aprobaciones explícitas.
- `test_omega.py`: suite unitaria independiente; incluye pruebas de lenguaje, memoria y aprobaciones, NetMap, lectura PCAP y PCAPdroid.
- `netmap.py`: escáner TCP connect acotado, compatible con la API de render que llama el núcleo.
- `pcap_inspector.py`: lector/analizador PCAP y PCAPNG ligero.
- `wirelab_live.py`: receptor UDP local para el exportador de PCAPdroid.
- `OMEGA.md`, `README.md`, `demo.omg`.
- `.github/workflows/omega-tests.yml`: workflow exclusivo de OMEGA.
- `security_lab.py` quedó como shim de compatibilidad; la suite ya no depende de él.
- Se corrigió un fixture de prueba que representaba mal la cabecera binaria PCAP y se movió el bloque `unittest.main()` al final para que las pruebas añadidas se descubran al ejecutar la suite.

## CI verificado

- Último commit comprobado: `6c001bd3f838c9f1bd2ec0bf67d96fdd9071b90b`.
- Run de Actions: `38562897852`, conclusión `success`.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38562897852
- Compilación de módulos y suite `test_omega` terminaron correctamente (61 pruebas en la última ejecución).
- CI no confirma todavía que todos los dispositivos Android funcionen ni valida captura PCAPdroid real en un móvil.

## Siguiente trabajo

1. Revisar límites y rutas en los adaptadores importados, incluyendo PCAPNG, datagramas malformados y salida de captura sin paquetes.
2. Añadir casos límite para la base SQLite y crear archivos.
3. En Termux, ejecutar:
   ```bash
   git clone https://github.com/JEEM244/Omega.git
   cd Omega
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
4. Corregir los fallos reales que aparezcan en el teléfono antes de considerar listo el proyecto.

## Recuperación

Actualizar este archivo antes de pausar: SHA, resultado real de CI y siguiente paso accionable. No borrar ni fusionar el repositorio histórico.
