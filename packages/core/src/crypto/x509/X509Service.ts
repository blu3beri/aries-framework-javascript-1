import { Crypto } from '@animo-id/askar-webcrypto'
import { id_ce_subjectAltName } from '@peculiar/asn1-x509'
import * as x509 from '@peculiar/x509'
import { injectable } from 'tsyringe'

import { Key } from '../Key'
import { KeyType } from '../KeyType'

import { X509Error } from './X509Error'

type Extension = Record<string, undefined | Array<{ type: string; value: string }>>

export type X509CertificateOptions = {
  algorithm: string
  publicKey: Key
  privateKey?: Uint8Array
  extensions?: Array<Extension>
  rawCertificate: Uint8Array
}

export class X509Certificate {
  public algorithm: string
  public publicKey: Key // TODO: or `Key` instance
  public privateKey?: Uint8Array // TODO: or `Key` instance
  public extensions?: Array<Extension>

  private rawCertificate: Uint8Array

  public constructor(options: X509CertificateOptions) {
    this.algorithm = options.algorithm
    this.extensions = options.extensions
    this.publicKey = options.publicKey
    this.privateKey = options.privateKey
    this.rawCertificate = options.rawCertificate
  }

  public static fromRawCertificate(rawCertificate: Uint8Array): X509Certificate {
    const certificate = new x509.X509Certificate(rawCertificate)
    return this.parseCertificate(certificate)
  }

  public static fromEncodedCertificate(encodedCertificate: string): X509Certificate {
    const certificate = new x509.X509Certificate(encodedCertificate)
    return this.parseCertificate(certificate)
  }

  private static parseCertificate(certificate: x509.X509Certificate): X509Certificate {
    // TODO: this breaks as for P-256 it will be `{name: 'ECDSA', namedCurve: 'P-256'}`
    // but for ed25519 it will be `[name: 'ed25519']`
    const algorithm = certificate.publicKey.algorithm.namedCurve
      ? certificate.publicKey.algorithm.namedCurve
      : certificate.publicKey.algorithm.name

    const publicKey = new Uint8Array(certificate.publicKey.rawData)
    const privateKey = certificate.privateKey ? new Uint8Array(certificate.privateKey.rawData) : undefined

    // TODO: remove this and validate properly from webcrypto-core algorithm to keyType of credo
    if (algorithm.toLowerCase() !== 'ecdsa') throw new X509Error(`Expected ECDSA algorithm, received: ${algorithm}`)

    const key = new Key(publicKey, KeyType.P256)

    return new X509Certificate({
      algorithm,
      publicKey: key,
      privateKey,
      extensions: certificate.extensions
        ?.map((e) => JSON.parse(JSON.stringify(e)))
        .map((e) => ({ [e.type]: e.names })) as Array<Extension>,
      rawCertificate: new Uint8Array(certificate.rawData),
    })
  }

  private getMatchingExtenstions<T>(name: string, type: string): Array<T> | undefined {
    const extensionsWithName = this.extensions
      ?.filter((e) => e[name])
      ?.flatMap((e) => e[name])
      ?.filter((e): e is Exclude<typeof e, undefined> => e !== undefined && e.type === type)
      ?.map((e) => e.value)

    return extensionsWithName as Array<T>
  }

  public get sanDnsNames() {
    const subjectAlternativeNameExtensionDns = this.getMatchingExtenstions<string>(id_ce_subjectAltName, 'dns')

    if (!subjectAlternativeNameExtensionDns || subjectAlternativeNameExtensionDns.length === 0) {
      throw new X509Error('No SubjectAlternativeName included in the X.509 certificate with a dns type')
    }

    if (!subjectAlternativeNameExtensionDns.some((e) => typeof e === 'string')) {
      throw new X509Error(
        'SubjectAlternativeName dns was found in the X.509 certificate, but it was not of type string'
      )
    }

    return subjectAlternativeNameExtensionDns.filter((e) => typeof e === 'string')
  }
}

@injectable()
export class X509Service {
  public constructor() {
    x509.cryptoProvider.set(new Crypto())
  }

  /**
   *
   * Validate a chain of X.509 certificates according to RFC 5280
   *
   * Additional validation:
   *   - Make sure atleast a single certificate is in the chain
   *
   */
  public async validateCertificateChain(certificateChain: Array<string>) {
    const certificate = certificateChain[0]
    if (!certificate) throw new Error('Certificate chain is empty')
  }

  /**
   *
   * Parses a base64-encoded X.509 certificate into a {@link X509Certificate}
   *
   */
  public parseCertificate(encodedCertificate: string): X509Certificate {
    return X509Certificate.fromEncodedCertificate(encodedCertificate)
  }
}
