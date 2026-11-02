// RedVital — identidad-service. Conexión al broker (Confluent.Kafka sobre
// librdkafka). Un usuario SCRAM propio, que solo escribe en su tema de
// auditoría (redvital.identidad.audit-recorded.v1).

using Confluent.Kafka;

namespace RedVital.Identidad.Api.Mensajeria;

public sealed class OpcionesKafka
{
    public bool Habilitado { get; set; }
    public string Servidores { get; set; } = "kafka:9092";
    public string Usuario { get; set; } = "identidad";
    public string? Clave { get; set; }
    public string Protocolo { get; set; } = "SaslPlaintext";

    public T Aplicar<T>(T config) where T : ClientConfig
    {
        config.BootstrapServers = Servidores;
        config.SecurityProtocol = Enum.Parse<SecurityProtocol>(Protocolo, ignoreCase: true);
        if (config.SecurityProtocol is SecurityProtocol.SaslPlaintext or SecurityProtocol.SaslSsl)
        {
            config.SaslMechanism = SaslMechanism.ScramSha512;
            config.SaslUsername = Usuario;
            config.SaslPassword = Clave;
        }
        return config;
    }
}

/// <summary>Productor único del servicio: idempotente y con confirmación de todas las réplicas.</summary>
public sealed class ProductorKafka : IDisposable
{
    public IProducer<string, string> Productor { get; }

    public ProductorKafka(OpcionesKafka opciones) =>
        Productor = new ProducerBuilder<string, string>(opciones.Aplicar(new ProducerConfig
        {
            EnableIdempotence = true,
            Acks = Acks.All,
            MessageTimeoutMs = 10_000,
            ClientId = "identidad",
        })).Build();

    public void Dispose()
    {
        Productor.Flush(TimeSpan.FromSeconds(5));
        Productor.Dispose();
    }
}
