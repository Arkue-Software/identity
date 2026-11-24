# Llave de desarrollo — T-303.1 / T-303.2

La llave privada generada aqui es material secreto, aunque solo se use en
Desarrollo y pruebas. No la versionas, compartas ni copies a QA o Produccion.
Las llaves se excluyen del control de versiones mediante `.gitignore`.

## Generar

Desde la raiz del repositorio, una vez por maquina:

```powershell
dotnet run --project herramientas/LlaveDePrueba -- generar-llave
```

Se escriben `dev-signing-key.private.pem` y `dev-signing-key.public.pem` en
`herramientas/LlaveDePrueba/llaves/`. La llave privada no sale de esa ubicacion
local; la publica se puede configurar en los servicios de desarrollo.

## Emitir tokens de prueba

```powershell
dotnet run --project herramientas/LlaveDePrueba -- emitir-token --perfil operador
dotnet run --project herramientas/LlaveDePrueba -- emitir-token --perfil admin_banco
dotnet run --project herramientas/LlaveDePrueba -- emitir-token --perfil servicio --cliente donacion
```

## Cargar en servicios locales

Configura la ruta privada local en Identity, solo en Development:

```powershell
$env:Jwt__LlavePrivadaDesarrollo = "C:\ruta\identity-service\herramientas\LlaveDePrueba\llaves\dev-signing-key.private.pem"
```

Campaign valida el JWKS de Identity por descubrimiento local. Si se ejecuta sin
Identity, puede configurarse `Jwt__LlavePublicaDesarrollo` con la ruta local a
`dev-signing-key.public.pem`; nunca configures la privada en Campaign.

Identity publica la llave de desarrollo en su JWKS con `kid = dev-key-1` solo
en Development. QA/Produccion no registra la implementacion que carga esta
llave; las pruebas de T-303.3 verifican el rechazo de tokens firmados con ella.
