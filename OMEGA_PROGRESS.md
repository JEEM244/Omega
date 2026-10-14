# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14.

## Repositorio y regla de trabajo

- Repositorio oficial: https://github.com/JEEM244/Omega
- Rama: `main`.
- OMEGA se desarrolla aquí, separado de `herramientas-termux`.
- El prototipo anterior y su historial quedan conservados en https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype.
- PR anterior, solo como referencia histórica; no fusionar ni eliminar para esta separación: https://github.com/JEEM244/herramientas-termux/pull/1
- No afirmar compatibilidad real con Termux hasta validar en un dispositivo Android.
- Escaneo y captura requieren autorización; la captura además requiere aceptar la VPN de PCAPdroid.

## Estado importado

Se importó la referencia OMEGA AI 0.3.0 con lenguaje declarativo, variables/condiciones, memoria SQLite, historial, clasificador Naive Bayes local y cola de acciones con aprobación explícita.

Archivos actuales:
- `omega_ai.py`: núcleo y REPL.
- `test_omega.py`: pruebas unitarias.
- `OMEGA.md`: documentación.
- `README.md`: guía del repositorio.
- `demo.omg`: programa demostrativo.

## Próximas tareas

1. Comprobar el contenido real de los archivos importados y revisar el diff respecto a la fuente histórica.
2. Añadir los adaptadores requeridos por las integraciones opcionales (`netmap.py`, `pcap_inspector.py`, `wirelab_live.py`) usando commits Git de bajo nivel, si la API de archivos sigue fallando.
3. Añadir un workflow CI exclusivo de este repositorio.
4. Ejecutar el CI: compilación y `python -m unittest -v test_omega`.
5. Revisar seguridad del parser, aprobaciones, rutas, SQLite y límites del laboratorio.
6. En Termux, ejecutar:
   ```bash
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
7. Resolver errores con el resultado real del dispositivo. No declarar listo hasta validar Android.

## Regla de recuperación

Antes de pausar, actualizar esta bitácora con SHA de commit, estado exacto de Actions y siguiente paso accionable. Mantener intacto el repo histórico.
