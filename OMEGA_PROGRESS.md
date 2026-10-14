# OMEGA AI — bitácora de progreso y recuperación

Actualizado: 2026-10-14. Primera importación del prototipo al repositorio independiente `JEEM244/Omega`.

## Repositorio fuente y continuidad

- Repositorio del proyecto: https://github.com/JEEM244/Omega
- Rama objetivo: `main`
- Código fuente de referencia/historial previo: https://github.com/JEEM244/herramientas-termux/tree/omega-ai-prototype
- PR de historial anterior (no fusionar ni borrar como parte de esta migración): https://github.com/JEEM244/herramientas-termux/pull/1
- La migración conserva la rama/PR anterior para trazabilidad. El desarrollo nuevo de OMEGA debe continuar solamente en este repositorio independiente.
- No afirmar compatibilidad Android comprobada hasta que el usuario ejecute las pruebas dentro de Termux.
- No ejecutar escaneos/capturas reales sin autorización explícita; la captura exige permiso VPN de Android.

## Versión importada

Se importó el núcleo OMEGA AI 0.3.0 con lenguaje declarativo, variables/condiciones, memoria SQLite, historial, clasificador Naive Bayes local desde cero, límites de recursos y cola de aprobación por operación. Incluye los adaptadores `netmap.py`, `pcap_inspector.py` y `wirelab_live.py` para mantener funcionales las pruebas de las integraciones opcionales.

## Archivos principales

- `omega_ai.py`: núcleo y REPL.
- `test_omega.py`: pruebas unitarias.
- `OMEGA.md`: guía del lenguaje y restricciones.
- `demo.omg`: demostración.
- `netmap.py`: escáner TCP connect restringido.
- `pcap_inspector.py`: lector/análisis PCAP/PCAPNG.
- `wirelab_live.py`: receptor UDP local para exportación PCAPdroid.
- `.github/workflows/omega-tests.yml`: CI específico de OMEGA.
- `README.md`: guía propia del repositorio.

## Próximos pasos

1. Comprobar en GitHub Actions que compilación y pruebas pasan en este repositorio.
2. Hacer revisión de seguridad del parser, rutas, SQLite, ejecución aprobada, parser PCAP y límites de captura.
3. Ejecutar en Termux:
   ```bash
   python -m py_compile omega_ai.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
   python -m unittest -v test_omega
   python omega_ai.py
   ```
4. Verificar el REPL con `ayuda`, `auditar` y un ejemplo de memoria no sensible. Probar la captura solo si se desea y se acepta el permiso VPN.
5. Corregir los errores con la salida real del dispositivo; no llamar finalizado al proyecto antes de esa prueba.

## Regla al pausar

Antes de detener el desarrollo, actualizar esta bitácora con SHA de commit, estado exacto de CI y el próximo paso accionable. No sobreescribir trabajo del usuario.
