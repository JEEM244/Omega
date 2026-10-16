# Historial de cambios

## OMEGA FORGE 0.2.0 — 2026-10-15

- Amplía la síntesis guiada por ejemplos para descubrir expresiones con hasta dos operaciones anidadas sobre una a tres entradas numéricas.
- Incorpora agregados `sum(xs)`, `min(xs)` y `max(xs)`, además de constantes y operadores aritméticos acotados.
- Añade límites explícitos de tamaño de fuente, nodos AST, profundidad sintáctica, iteraciones, colecciones y pasos del intérprete.
- Limita también la profundidad de anidamiento JSON de manifiestos, entradas y capacidades para mantener un comportamiento consistente entre versiones de Python.
- Permite guardar una capacidad validada como JSON en el workspace mediante una operación `file_create` que requiere aprobación.
- Conserva los casos de validación reservados y los vuelve a comprobar antes de ejecutar una capacidad guardada.
- Añade un catálogo local acotado y metadatos de procedencia para versiones evolucionadas.
- Añade propuestas de evolución que comparan una capacidad existente con una nueva síntesis. Solo propone una versión nueva si la anterior falla los ejemplos/validación o si la nueva usa menos pasos estimados; nunca sobrescribe la versión anterior.
- La métrica de pasos representa trabajo del intérprete restringido, no velocidad nativa ni corrección universal.
- La evolución automática del código central de OMEGA no está implementada. FORGE evoluciona funciones/capacidades restringidas, no el núcleo de Python.
- CI de referencia para el código de esta etapa: 123 pruebas en Python 3.10, 3.11, 3.12 y 3.13. La validación real en Termux debe repetirse en el dispositivo.

