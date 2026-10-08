# identity-service

Servicio de Identidad de RedVital (.NET 10 / ASP.NET Core). Emite sesiones y
tokens de acceso RS256, publica claves públicas (JWKS) y registra eventos de
auditoría. El esquema se administra en `Arkue-Software/databases`, no con
migraciones EF Core desde este servicio.

| Ruta | Tarea |
|---|---|
| `POST /v1/sesiones` | T-304.2, T-304.3 |
| `GET /.well-known/jwks.json` | T-304.4 |
| `POST /v1/sesiones/renovacion` | T-330.1 |
| `DELETE /v1/sesiones/actual` | T-330.2 |
| `POST /internal/v1/sesiones/servicio` | T-330.3 (solo gateway/red interna) |
| `POST /internal/v1/auditoria/denegaciones` | T-330.4 (solo gateway) |

## Ejecución local

Desde `Arkue-Software/databases`, crea los secretos y levanta `db-identidad`
y `migracion-identidad` siguiendo su README. La base se mantiene en la red
interna `redvital_identidad_data` y no publica un puerto al host.

Genera la llave de desarrollo localmente, una vez por máquina:

```powershell
dotnet run --project herramientas/LlaveDePrueba -- generar-llave
```

La API ejecutada con `dotnet run` en el host no puede conectarse a la base
aislada. Para ejecutar la API contra PostgreSQL se necesita un contenedor
conectado a `redvital_identidad_data`, usando `Host=db-identidad;Port=5432`.
Este repositorio aún no incluye Dockerfile ni composición de runtime para ese
contenedor. La llave privada es secreta incluso en desarrollo: móntala como
secreto al ejecutar Identidad y nunca la versionas ni compartas.

Mientras no exista esa composición, valida el código con las pruebas descritas
abajo; el build y las pruebas no equivalen a un arranque funcional conectado a
PostgreSQL.

La aplicación no crea ni migra el esquema al iniciar. Si faltan la base, las
migraciones o la llave configurada, el inicio falla explícitamente.

## Pruebas

Ejecuta `dotnet test RedVital.Identidad.sln` desde la raíz del repositorio.
