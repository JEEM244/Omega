# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio oficial y reglas

- Repositorio independiente: https://github.com/JEEM244/Omega
- Rama de desarrollo: `main`.
- El prototipo anterior queda preservado en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype y su PR histórico permanece sin fusionar: https://github.com/JEEM244/herramientas-termux/pull/1
- El trabajo nuevo de OMEGA debe continuar en este repositorio solamente.
- No afirmar que ya funciona en Android/Termux real hasta validar en el dispositivo.
- Escaneo de red solo con autorización; captura solo con autorización y permiso VPN de PCAPdroid.

## Estado actual

- Núcleo OMEGA AI 0.3.0 importado: lenguaje declarativo, variables/condiciones, aprobaciones explícitas, memoria SQLite, historial, planificador simbólico y clasificador Naive Bayes pequeño entrenado localmente.
- Archivos en el repo: `omega_ai.py`, `test_omega.py`, `OMEGA.md`, `README.md`, `OMEGA_PROGRESS.md`, `demo.omg`, `netmap.py`, `pcap_inspector.py`, `wirelab_live.py`, `.github/workflows/omega-tests.yml`, `security_lab.py` (shim compatible para pruebas históricas).
- Corrección de integración aplicada a NetMap: exporta `render_text`, que el núcleo usa para reportar el escaneo.

## CI

- Último commit con CI verificado: `c1b5cffd3a8e39d645b5f151122d8e77d0a5b377`.
- GitHub Actions run `38561282731`: compilación y suite OMEGA finalizaron con `success`.
- Ejecución: https://github.com/JEEM244/Omega/actions/runs/38561282731
- CI comprueba sintaxis y 52 pruebas unitarias OMEGA en Ubuntu. No valida por sí sola Android ni la captura real PCAPdroid.

## Próximas tareas

1. Inspeccionar dependencias y diferencias del código importado; la migración está orientada a preservar el MVP, pero los adaptadores deben recibir pruebas propias.
2. Añadir pruebas de NetMap/WireLab y CI completo del repo independiente, comprobar salida de los tests del núcleo.
3. Revisar parser, autorización, SQLite, rutas, manejo de PCAP y captura.
4. El usuario ejecutará dentro de Termux:
   ```bash
   git clone https://github.com/JEEM244/Omega.git
   cd Omega
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
5. Corregir fallos según la salida real del teléfono; mantener explícito qué se comprobó en CI y qué no.

## Pausa / recuperación

Antes de detener trabajo, actualizar este archivo con el SHA más reciente, estado real de GitHub Actions y un siguiente paso accionable. No borrar ni fusionar el repo histórico.
