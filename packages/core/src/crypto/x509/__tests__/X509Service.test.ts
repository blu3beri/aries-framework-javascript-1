import { X509Service } from '../X509Service'

describe('X509Service', () => {
  it('should parse a valid X.509 certificate', () => {
    const certificate =
      'MIIBmDCCAT6gAwIBAgIQJUfvUxQSan3Pf5Sj57NykDAKBggqhkjOPQQDAjAnMQswCQYDVQQGEwJOTDEYMBYGA1UEChMPQW5pbW8gU29sdXRpb25zMB4XDTI0MDYyMTExNTYwMVoXDTI1MDYyMTExNTYwMVowJzELMAkGA1UEBhMCTkwxGDAWBgNVBAoTD0FuaW1vIFNvbHV0aW9uczAwMAoGCCqGSM49BAMCAyIAAnqeoIYDoOfcv033Ch9TLu4OofEMr2ftbLLzNS0UYDbeo3UwczAdBgNVHQ4EFgQUYbXqzXNyO3vmf3eLkQDD59Ho8ywwKAYDVR0RBCEwH4IKcGFyYWR5bS5pZIIRd2FsbGV0LnBhcmFkeW0uaWQwEwYDVR0RBAwwCoIIYW5pbW8uaWQwEwYDVR0RBAwwCoYIYW5pbW8uaWQwCgYIKoZIzj0EAwIDSAAwRQIhAMdH/f5Ui83FaKW0n4zxJ8gmraH7vAkhSq2UnI+4hEolAiBfMJZF+UghmfE5mFS/a3i7+4QozFzzOdirDFCUe2TbRg=='
    const x509Service = new X509Service()

    const x509Certificate = x509Service.parseCertificate(certificate)

    expect(x509Certificate).toMatchObject({
      sanDnsNames: expect.arrayContaining(['paradym.id', 'wallet.paradym.id', 'animo.id']),
      sanUriNames: expect.arrayContaining(['animo.id']),
    })

    expect(x509Certificate.publicKey.publicKey.length).toStrictEqual(33)
  })
})
