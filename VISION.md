# OMEGA — visión y dirección del proyecto

## Visión

**Presencia en el mundo. Inolvidable.**

OMEGA busca convertirse en una tecnología original, útil y duradera: un sistema capaz de descubrir soluciones, crear capacidades y mejorar lo que construye, con resultados que otras personas puedan comprobar y aprovechar.

Esta frase es la aspiración del proyecto, no una afirmación de que OMEGA ya posea inteligencia general ni una garantía de reconocimiento mundial.

## Misión técnica actual

Construir, paso a paso, un motor local de descubrimiento y evolución de software que pueda:

1. Recibir ejemplos y una meta concreta.
2. generar soluciones candidatas dentro de una gramática restringida;
3. probarlas contra ejemplos de entrenamiento y casos de validación reservados;
4. conservar una capacidad que pase las pruebas;
5. reutilizarla sin ejecutar Python arbitrario;
6. proponer una nueva versión cuando demuestre una mejora medible, sin sobrescribir la anterior.

La primera demostración es **OMEGA FORGE 0.2.0**: síntesis acotada de expresiones numéricas, catálogo local de capacidades, revalidación antes de cada uso y propuestas de evolución con aprobación.

## Qué significa «evolucionar»

Una modificación solo cuenta como mejora si se demuestra una ventaja en una métrica definida y no rompe los criterios de corrección. La memoria o el cambio de código por sí solos no cuentan como evolución.

- La corrección se comprueba con pruebas reproducibles.
- La puntuación actual de FORGE mide pasos de su intérprete restringido; no es una medición de velocidad nativa.
- Una capacidad que no mejora se conserva sin cambios.
- Las nuevas versiones se guardan con otro nombre y conservan evidencia de validación y procedencia.
- La evolución del código central de OMEGA todavía no está implementada; no se debe describir FORGE como un sistema que reescribe su propio núcleo.

## Principios que no deben cambiar

- **Utilidad antes que novedad:** una función debe resolver un problema demostrable.
- **Evidencia antes que afirmaciones:** distinguir entre candidato, validado en casos de prueba y comprobado en el dispositivo real.
- **Un núcleo coherente:** evitar añadir módulos sin una interfaz y una finalidad claras.
- **Autonomía gradual:** experimentar en límites definidos; solicitar aprobación para cambios persistentes.
- **Recuperabilidad:** no sobrescribir capacidades ni el núcleo; conservar una versión anterior.
- **Local primero:** mantener el funcionamiento básico en Python/Termux, sin root y sin depender obligatoriamente de la nube.
- **Honestidad técnica:** no llamar inteligencia general a un conjunto de reglas o a un sintetizador limitado.

## Qué queda fuera por ahora

- Reescritura automática y sin supervisión del núcleo Python.
- Ejecución de código generado mediante `eval`, `exec` o shell.
- Afirmaciones de que OMEGA supera a Claude, ChatGPT u otras IA sin pruebas comparables.
- Añadir funciones solo para aumentar el número de comandos.
- Declarar compatibilidad completa con Android antes de validar el dispositivo real.

## Ruta de desarrollo

### Etapa 1 — Demostración reproducible
Completar y probar FORGE 0.2.0 en Termux: descubrir una función, guardarla con aprobación, reutilizarla y verificar que no propone cambios innecesarios.

### Etapa 2 — Ampliar el descubrimiento
Extender la síntesis a una nueva familia de problemas únicamente cuando haya un caso de uso real, un conjunto de pruebas y límites de recursos claros.

### Etapa 3 — Evolución de capacidades
Mantener versiones, evidencias, procedencia y comparación de resultados. Rechazar cambios que no mejoren una métrica relevante.

### Etapa 4 — Propuestas de cambios al núcleo
Diseñar primero un flujo de parches revisables y una estrategia de recuperación. No ejecutar código modificado de forma automática en el entorno principal; la seguridad del banco de pruebas debe demostrarse antes de habilitarlo.

### Etapa 5 — Validación en el dispositivo
Ejecutar las pruebas en Termux real, medir recursos y confirmar por separado cualquier integración con PCAPdroid. CI no sustituye esta validación.

## Criterio para aceptar una nueva función

Antes de implementarla, debe responderse:

1. ¿Qué problema concreto resuelve?
2. ¿Qué evidencia demostrará que funciona?
3. ¿Qué límites de recursos y seguridad necesita?
4. ¿Cómo se revierte si falla?
5. ¿Aporta una capacidad nueva o mejora una existente?

Si no hay respuestas claras, la idea se registra para después; no se añade al núcleo todavía.
