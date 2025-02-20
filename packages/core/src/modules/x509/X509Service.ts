import type {
  X509ValidateCertificateChainOptions,
  X509GetLeafCertificateOptions,
  X509ParseCertificateOptions,
  X509CreateCertificateOptions,
} from './X509ServiceOptions'

import { injectable } from 'tsyringe'

import { AgentContext } from '../../agent'
import { CredoWebCrypto } from '../../crypto/webcrypto'

import { X509Certificate } from './X509Certificate'
import { X509Error } from './X509Error'
import { Certificate, CertificateChainValidationEngine, ICryptoEngine } from 'pkijs'

@injectable()
export class X509Service {
  /**
   *
   * Validate a chain of X.509 certificates according to RFC 5280
   *
   * This function requires a list of base64 encoded certificates and, optionally, a certificate that should be found in the chain.
   * If no certificate is provided, it will just assume the leaf certificate
   *
   * The leaf certificate should be the 0th index and the root the last
   *
   * Additional validation:
   *   - Make sure atleast a single certificate is in the chain
   *   - Check whether a certificate in the chain matches with a trusted certificate
   */
  public static async validateCertificateChain(
    agentContext: AgentContext,
    {
      certificateChain,
      certificate = certificateChain[0],
      verificationDate = new Date(),
      trustedCertificates,
    }: X509ValidateCertificateChainOptions
  ) {
    const webCrypto = new CredoWebCrypto(agentContext)
    if (certificateChain.length === 0) throw new X509Error('Certificate chain is empty')

    const engine = new CertificateChainValidationEngine({
      certs: certificateChain.map((c) => Certificate.fromBER(X509Certificate.fromEncodedCertificate(c).rawCertificate)),
      trustedCerts: trustedCertificates?.map((c) => Certificate.fromBER(X509Certificate.fromEncodedCertificate(c).rawCertificate)),
      checkDate: verificationDate
    })

    console.log({
      certs: certificateChain.map((c) => X509Certificate.fromEncodedCertificate(c).subject),
      trustedCertificates: trustedCertificates?.map((c) => X509Certificate.fromEncodedCertificate(c).subject),
      checkDate: verificationDate
    })

    const chain = await engine.verify({}, webCrypto as unknown as ICryptoEngine)

    if (!chain.result) {
      throw new X509Error(chain.resultMessage);
    }

    return chain.result
  }

  /**
   *
   * Parses a base64-encoded X.509 certificate into a {@link X509Certificate}
   *
   */
  public static parseCertificate(
    _agentContext: AgentContext,
    { encodedCertificate }: X509ParseCertificateOptions
  ): X509Certificate {
    const certificate = X509Certificate.fromEncodedCertificate(encodedCertificate)

    return certificate
  }

  public static getLeafCertificate(
    _agentContext: AgentContext,
    { certificateChain }: X509GetLeafCertificateOptions
  ): X509Certificate {
    if (certificateChain.length === 0) throw new X509Error('Certificate chain is empty')

    const certificate = X509Certificate.fromEncodedCertificate(certificateChain[0])

    return certificate
  }

  public static async createCertificate(agentContext: AgentContext, options: X509CreateCertificateOptions) {
    const webCrypto = new CredoWebCrypto(agentContext)

    const certificate = await X509Certificate.create(options, webCrypto)

    return certificate
  }
}
