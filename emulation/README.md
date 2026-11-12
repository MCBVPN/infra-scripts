# Laboratorio de emulación de ataques

Recrea, sobre objetivos simulados y propios, las técnicas de tres ataques
recientes, y mide qué pasos detectan nuestras reglas y cuánto tardan.

| Escenario | Inspirado en | Qué se emula |
|---|---|---|
| `cold-chain` | Ataques a la refrigeración de supermercados (nov. 2026) | Panel con credenciales de fábrica, alarma desactivada y consigna subida por Modbus/TCP |
| `web-postex` | Lo que ocurre tras las intrusiones de PeopleSoft y PHP2Shell | Fichero de script en el directorio web y comandos lanzados por el servidor web |
| `exfil` | Extorsión sin cifrado | Listado y descarga masiva de un almacén de documentos |

No se explota ninguna vulnerabilidad real. Los objetivos son señuelos incluidos
en este directorio, los datos son falsos y el "web shell" solo ejecuta cuatro
comandos fijos de solo lectura. Sin dependencias: solo Node 18 o superior.

## Uso

Todo en local (señuelo, tráfico normal, ataque y marcador):

```
node emulation/run.js all
node emulation/run.js cold-chain --json scorecard.json
node emulation/run.js all --disable CC-04,EXF-02    # ver qué aporta cada regla
node emulation/run.js all --strict                  # sale con 1 si hay pasos sin detectar o falsos positivos
```

También está el workflow `SolveBeat Attack Emulation Lab`, que hace lo mismo en
un runner y guarda el marcador como artefacto.

## En nuestra red, contra el SIEM real

El modo local mide la lógica de las reglas, no el tiempo real de detección.
Para medir eso, el señuelo y el ataque se ejecutan en dos máquinas nuestras y
se comprueba qué ven los sensores reales entre ambas:

```
# En el host señuelo (dirección privada)
node emulation/run.js serve cold-chain --bind 10.0.0.5 --trusted 10.0.0.9

# En el host atacante, tras añadir 10.0.0.5 a emulation/targets.allow
node emulation/run.js attack cold-chain --target 10.0.0.5
```

Las dos salidas llevan marca de tiempo: la diferencia entre cada `STEP` y la
alerta correspondiente en el SIEM es el tiempo real de detección.

Salvaguardas: el señuelo solo escucha en loopback o en direcciones privadas, y
el atacante solo acepta loopback o direcciones privadas escritas en
`targets.allow`. Las direcciones públicas se rechazan siempre.

## Reglas para producción

`rules/` contiene las equivalentes para sensores reales:

- `ot-modbus.rules`: Suricata, para el escenario `cold-chain`.
- `web-postex.sigma.yml`: Sigma, para el escenario `web-postex`.

Hay que ajustarlas al entorno (variables de red, mapa de registros del
controlador, rutas de subida) antes de activarlas. El escenario `exfil` no
tiene regla portable: depende de los registros de acceso de cada aplicación.

## Límites

- La telemetría la generan los propios señuelos; sustituye a auditd, FIM y
  registros de acceso, no los prueba.
- Las latencias del modo local son de milisegundos porque no hay transporte
  de registros. No son representativas de producción.
- Las reglas basadas en dirección de origen solo se ejercitan en Linux en modo
  local (el atacante sale desde 127.0.0.2).
