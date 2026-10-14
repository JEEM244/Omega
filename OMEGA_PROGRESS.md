# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio oficial y reglas

- Repositorio independiente: https://github.com/JEEM244/Omega
- Rama de trabajo: `main`.
- El prototipo anterior se conserva intacto en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype; su PR histórico continúa sin fusionar: https://github.com/JEEM244/herramientas-termux/pull/1
- El desarrollo nuevo de OMEGA se hace aquí, sin depender del lanzador del repo anterior.
- No afirmar compatibilidad real en Android hasta recibir resultado de Termux en el dispositivo.
- Escaneo únicamente en objetivos autorizados. Captura solo después de autorización y permiso VPN de PCAPdroid.

## Estado actual

- OMEGA AI 0.3.0 importado: lenguaje declarativo, variables y condiciones, planificador simbólico, memoria persistente SQLite, historial y clasificador Naive Bayes pequeño con ejemplos locales aprobados.
- Archivos centrales: `omega_ai.py`, `test_omega.py`, `OMEGA.md`, `README.md`, `demo.omg`.
- Integraciones propias de este repositorio: `netmap.py`, `pcap_inspector.py`, `wirelab_live.py`.
- CI propio: `.github/workflows/omega-tests.yml`. Las pruebas de núcleo no dependen de `security_lab.py` del repositorio anterior.
- Se añadieron pruebas autónomas de política/puertos y socket loopback de NetMap, decodificación TCP y lectura clásica PCAP, además del parser de datagrama y el comando explícito de PCAPdroid.
- Se corrigió la cabecera binaria del fixture PCAP de pruebas usando `bytes.fromhex("d4c3b2a1")`.

## CI verificado

- Commit: `23f7b02b1d08c22d4c671e0af1fdbde8579224cc`.
- Run de GitHub Actions `38562478171`: éxito; compilación y suite completa terminadas correctamente.
- Enlace: https://github.com/JEEM244/Omega/actions/runs/38562478171
- La suite anterior contenía 61 pruebas; con las nuevas pruebas de integración la suite pasa ahora completa (ver salida del run enlazado).
- La CI no demuestra compatibilidad con todas las versiones de Android ni confirma una captura PCAPdroid real en el teléfono.

## Próximos pasos

1. Revisar las implementaciones de límites, parser y rutas en los adaptadores importados; la importación autónoma usa versiones ligeras y necesita evaluación continua.
2. Considerar tests adicionales de PCAPNG, paquetes malformados, timeout y captura acotada.
3. En Termux, ejecutar:
   ```bash
   git clone https://github.com/JEEM244/Omega.git
   cd Omega
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
4. Atender los errores reales del dispositivo antes de considerar listo el proyecto.

## Recuperación al pausar

Actualizar este archivo con SHA actual, resultado de CI y siguiente paso concreto. Mantener intacto el historial previo.
