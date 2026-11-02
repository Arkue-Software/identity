// RF-01 — Alta pública de la cuenta del donante y salida de la auditoría por
// la bandeja (EV-10): cada registro deja su evento en la misma transacción.

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Infraestructura.Auditoria;
using Xunit;

namespace RedVital.Identidad.Pruebas;

public class CuentaDonantePruebas
{
    private const string Cliente = "registro-publico";

    private static CrearCuentaDonante Caso(Entorno e) => new(e.Contexto, e.Auditoria);

    [Fact]
    public async Task Crea_la_cuenta_como_donante_y_la_audita_como_anonima()
    {
        var e = new Entorno();

        var r = await Caso(e).EjecutarAsync(new("Ana.Rojas@Correo.co", "Clave-Larga-2026", "Ana Rojas"), Cliente, "clave-1", "corr-a");

        Assert.Equal(ResultadoCuenta.Creada, r.Resultado);
        var usuario = await e.Contexto.Usuarios.SingleAsync(u => u.Id == r.UsuarioId);
        Assert.Equal("ana.rojas@correo.co", usuario.Correo);
        Assert.Equal("donante", usuario.RolCodigo);
        Assert.NotEqual("Clave-Larga-2026", usuario.CredencialHash);
        var registro = await e.Contexto.RegistroAuditoriaIdent.SingleAsync();
        Assert.Equal("anonimo", registro.ActorTipo);
        Assert.Null(registro.ActorId);
        Assert.Equal(r.UsuarioId, registro.RecursoId);
    }

    [Fact]
    public async Task El_reenvio_con_la_misma_clave_devuelve_la_misma_cuenta()
    {
        var e = new Entorno();
        var primera = await Caso(e).EjecutarAsync(new("luis@correo.co", "Clave-Larga-2026", "Luis"), Cliente, "clave-2", "corr-b");

        var segunda = await Caso(e).EjecutarAsync(new("luis@correo.co", "Clave-Larga-2026", "Luis"), Cliente, "clave-2", "corr-c");

        Assert.Equal(ResultadoCuenta.Reenvio, segunda.Resultado);
        Assert.Equal(primera.UsuarioId, segunda.UsuarioId);
        Assert.Equal(1, await e.Contexto.Usuarios.CountAsync());
    }

    [Fact]
    public async Task Un_correo_con_cuenta_da_conflicto_y_una_clave_reusada_con_otros_datos_se_rechaza()
    {
        var e = new Entorno();
        await Caso(e).EjecutarAsync(new("eva@correo.co", "Clave-Larga-2026", "Eva"), Cliente, "clave-3", "corr-d");

        var mismoCorreo = await Caso(e).EjecutarAsync(new("eva@correo.co", "Clave-Larga-2026", "Eva"), Cliente, "clave-4", "corr-e");
        var claveReusada = await Caso(e).EjecutarAsync(new("otra@correo.co", "Clave-Larga-2026", "Otra"), Cliente, "clave-3", "corr-f");

        Assert.Equal(ResultadoCuenta.CorreoExistente, mismoCorreo.Resultado);
        Assert.Equal(ResultadoCuenta.ClaveReutilizada, claveReusada.Resultado);
    }

    [Theory]
    [InlineData("sin-arroba", "Clave-Larga-2026", "Nombre")]
    [InlineData("a@b.co", "corta", "Nombre")]
    [InlineData("a@b.co", "SoloLetrasSinNumeros", "Nombre")]
    [InlineData("a@b.co", "12345678901234", "Nombre")]
    [InlineData("a@b.co", "Clave-Larga-2026", " ")]
    public async Task Datos_invalidos_no_crean_nada(string correo, string credencial, string nombre)
    {
        var e = new Entorno();

        var r = await Caso(e).EjecutarAsync(new(correo, credencial, nombre), Cliente, "clave-5", "corr-g");

        Assert.Equal(ResultadoCuenta.DatosInvalidos, r.Resultado);
        Assert.Equal(0, await e.Contexto.Usuarios.CountAsync());
        Assert.Equal(0, await e.Contexto.EventosSalida.CountAsync());
    }

    [Fact]
    public async Task Cada_registro_de_auditoria_deja_su_evento_en_la_bandeja()
    {
        var e = new Entorno();
        await Caso(e).EjecutarAsync(new("sol@correo.co", "Clave-Larga-2026", "Sol"), Cliente, "clave-6", "corr-h");

        var registro = await e.Contexto.RegistroAuditoriaIdent.SingleAsync();
        var evento = await e.Contexto.EventosSalida.SingleAsync();
        Assert.Equal(RegistradorAuditoria.Tema, evento.Tema);
        Assert.Equal("audit.recorded", evento.Tipo);
        Assert.Equal(1, evento.VersionEsquema);
        Assert.Equal("corr-h", evento.Clave);
        Assert.Equal("pendiente", evento.Estado);

        using var carga = JsonDocument.Parse(evento.Carga);
        var raiz = carga.RootElement;
        Assert.Equal(registro.Id, raiz.GetProperty("id").GetGuid());
        Assert.Equal("anonimo", raiz.GetProperty("actor_tipo").GetString());
        Assert.Equal("alta_cuenta_donante", raiz.GetProperty("operacion").GetString());
        Assert.Equal("usuario", raiz.GetProperty("recurso_tipo").GetString());
        Assert.Equal("permitido", raiz.GetProperty("resultado").GetString());
        Assert.Equal("corr-h", raiz.GetProperty("correlacion_id").GetString());
        Assert.True(raiz.TryGetProperty("ocurrido_en", out _));
        // La carga es la estructura común: ni correo ni nombre.
        Assert.DoesNotContain("sol@correo.co", evento.Carga);
    }
}
