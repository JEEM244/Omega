# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio y reglas

- Repositorio independiente oficial: https://github.com/JEEM244/Omega
- Rama de desarrollo: `main`.
- El prototipo previo queda preservado en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype y el PR histórico permanece sin fusionar: https://github.com/JEEM244/herramientas-termux/pull/1
- OMEGA nuevo se desarrolla en este repositorio. Sus pruebas no dependen del lanzador de herramientas-termux.
- No afirmar compatibilidad real en Android hasta que la salida de pruebas provenga del Termux del usuario.
- Escaneo solo en objetivos autorizados; captura únicamente con autorización y permiso VPN de PCAPdroid.

## Código actual

- `omega_ai.py`: núcleo 0.3.0, lenguaje declarativo, REPL, planificador, memoria SQLite e intenciones Naive Bayes locales.
- `test_omega.py`: pruebas autónomas del núcleo (eliminada dependencia de `security_lab.py`).
- `OMEGA.md`, `README.md`, `demo.omg`.
- `netmap.py`, `pcap_inspector.py`, `wirelab_live.py`: adaptadores del laboratorio; el escaneo tiene renderer requerido por la integración.
- `.github/workflows/omega-tests.yml`: CI propio.
- No hay dependencia obligatoria de `herramientas-termux` para iniciar OMEGA.

## CI verificado

- Commit más reciente comprobado: `4d4b28bb77ada25381fe217f9e5700a818c0427e`.
- GitHub Actions run `38561635557`: `success` (compilación y suite OMEGA).
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38561635557
- La CI no demuestra todavía compatibilidad con el Android real ni captura PCAPdroid en el dispositivo.

## Próximos pasos

1. Añadir tests dedicados para los adaptadores NetMap, PCAP/PCAPNG y el parser de datagramas PCAPdroid, además de la suite de 52 tests núcleo.
2. Revisar seguridad del parser, las rutas de archivos y base de datos, el flujo de aprobación y los límites de carga.
3. El usuario ejecuta en Termux:
   ```bash
   git clone https://github.com/JEEM244/Omega.git
   cd Omega
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
4. Diagnosticar los errores concretos del móvil antes de dar por terminado el proyecto.

## Recuperación

Antes de pausar, guardar en esta bitácora el commit más reciente, resultado real de CI y el siguiente paso accionable. No eliminar ni fusionar el repo histórico.
