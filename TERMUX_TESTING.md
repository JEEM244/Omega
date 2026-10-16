# Guía de validación manual en Termux

Esta guía complementa las pruebas automatizadas de GitHub Actions. No requiere root y las primeras comprobaciones funcionan sin conexión a Internet después de instalar Python y clonar el repositorio.

## 1. Comprobar compilación y pruebas

Desde la carpeta del repositorio:

```bash
python -m py_compile omega_ai.py omega_forge.py test_omega.py netmap.py pcap_inspector.py wirelab_live.py
python -m unittest -v test_omega
python omega_ai.py
```

La suite debe finalizar con `OK`. El número de pruebas puede aumentar en versiones futuras.

## 2. Verificar la aprobación de operaciones

En el prompt `omega>`, ejecuta:

```text
ayuda
auditar
pendientes
```

Revisa la descripción y el número que OMEGA muestre entre corchetes. Si la auditoría aparece como `[1]`, escribe `aprobar 1`; usa siempre el número real, no la palabra `ID`.

OMEGA vuelve a describir la operación y pregunta si la autorizas. Escribe exactamente `SI` solo después de revisar la descripción. Después consulta:

```text
historial 5
pendientes
```

La auditoría es local y no consulta la red.

## 3. Verificar memoria persistente

En el prompt:

```text
recordar "prueba" = "memoria persistente OMEGA"
pendientes
```

Aprueba la operación de memoria usando el número que se muestre y confirma con `SI`. Luego solicita:

```text
leer "prueba"
pendientes
```

Aprueba la lectura de memoria de la misma manera. Para comprobar que persiste, escribe `salir`, vuelve a ejecutar `python omega_ai.py` y repite `leer "prueba"`, aprobando la operación pendiente.

## 4. OMEGA FORGE 0.2 — descubrir y reutilizar una capacidad

Esta prueba es local; no requiere PCAPdroid, root ni conexión después de clonar el repositorio.

Primero, ejecuta el manifiesto de demostración:

```bash
python omega_forge.py --synthesize forge_max_discovery.json
```

Después, en la terminal de OMEGA:

```text
/forja descubrir forge_max_discovery.json
/forja guardar forge_max_discovery.json maximo.json
/pendientes
/aprobar ID_REAL
SI
/forja lista
/forja usar maximo.json "[9, 1, 5]"
/forja evolucionar forge_max_discovery.json maximo.json maximo_v2.json
```

Sustituye `ID_REAL` por el identificador que aparece en la cola y autoriza únicamente después de revisar la descripción. El resultado de `usar` debe ser `9`. La orden `evolucionar` debería indicar que no hace falta una nueva versión si la capacidad guardada ya es equivalente y no reduce los pasos estimados. No debería crear una operación pendiente en ese caso.

FORGE conserva los casos de validación y vuelve a comprobarlos antes de cada uso. Esta función evoluciona capacidades aritméticas restringidas; no modifica el código central de OMEGA.

## 5. Captura PCAPdroid — dejar para una prueba separada

No es necesaria para validar el núcleo. Cuando estés listo para hacerla, instala/configura PCAPdroid, entiende qué tráfico puede registrar y acepta conscientemente el permiso VPN de Android. OMEGA limita cada captura a un máximo de 60 segundos y 500 paquetes.

Una prueba pequeña puede empezar con `capturar 5 20`. Revisa la operación pendiente, apruébala con su número real y confirma con `SI`. Si Android o PCAPdroid pide autorización VPN, revísala antes de concederla. No ejecutes capturas en redes o dispositivos ajenos sin autorización.

## Qué no demuestra esta guía

Que las pruebas unitarias y la auditoría SQLite pasen no demuestra que la exportación real de PCAPdroid funcione en todos los dispositivos Android. Esa integración debe confirmarse por separado en el teléfono.
