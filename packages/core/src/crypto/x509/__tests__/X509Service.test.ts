import { X509Service } from '../X509Service'

describe('X509Service', () => {
  it('should parse a valid X.509 certificate', () => {
    const certificate =
      'MIIBgzCCASmgAwIBAgIQValJOvn79p/PF6JKdoUpmzAKBggqhkjOPQQDAjAnMQswCQYDVQQGEwJOTDEYMBYGA1UEChMPQW5pbW8gU29sdXRpb25zMB4XDTI0MDYxNDE1MDMxN1oXDTI1MDYxNDE1MDMxN1owJzELMAkGA1UEBhMCTkwxGDAWBgNVBAoTD0FuaW1vIFNvbHV0aW9uczAwMAoGCCqGSM49BAMCAyIAA/3CkZpF4LO4EXwkhhJy7Tmw0iF5bAi0KOLJyQXXaAwPo2AwXjAdBgNVHQ4EFgQUzQywQNdPp60aoWDeFK/GjkORaBYwKAYDVR0RBCEwH4IKcGFyYWR5bS5pZIIRd2FsbGV0LnBhcmFkeW0uaWQwEwYDVR0RBAwwCoIIYW5pbW8uaWQwCgYIKoZIzj0EAwIDSAAwRQIgUe1Nbm7/QAAgHfKA2Qtc+8Ipc4xZRKKVq+1ipqZCSgoCIQDz9BveDgWvMC0mF3QXRH1HgR8BqHIYUNcaYVWxzBVBxQ=='
    const x509Service = new X509Service()

    const x509Certificate = x509Service.parseCertificate(certificate)

    expect(x509Certificate).toMatchObject({
      sanDnsNames: expect.arrayContaining(['paradym.id', 'wallet.paradym.id', 'animo.id']),
    })
  })
})
