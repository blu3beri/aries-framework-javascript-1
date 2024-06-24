import type { AgentContext } from '../../agent'
import type { Key, Wallet } from '@credo-ts/core'

import { Crypto } from '@animo-id/askar-webcrypto'
import * as x509 from '@peculiar/x509'

import { InMemoryWallet } from '../../../../../tests/InMemoryWallet'
import { getAgentConfig, getAgentContext } from '../../../tests/helpers'
import { DidKey } from '../../modules/dids'
import { JsonEncoder, TypedArrayEncoder } from '../../utils'
import { JwsService } from '../JwsService'
import { KeyType } from '../KeyType'
import { JwaSignatureAlgorithm } from '../jose/jwa'
import { getJwkFromKey } from '../jose/jwk'

import * as didJwsz6Mkf from './__fixtures__/didJwsz6Mkf'
import * as didJwsz6Mkv from './__fixtures__/didJwsz6Mkv'
import * as didJwszDnaey from './__fixtures__/didJwszDnaey'

describe('JwsService', () => {
  let wallet: Wallet
  let agentContext: AgentContext
  let jwsService: JwsService
  let didJwsz6MkfKey: Key
  let didJwsz6MkvKey: Key
  let didJwszDnaeyKey: Key

  beforeAll(async () => {
    const config = getAgentConfig('JwsService')
    wallet = new InMemoryWallet()
    agentContext = getAgentContext({
      wallet,
    })
    await wallet.createAndOpen(config.walletConfig)

    jwsService = new JwsService()
    didJwsz6MkfKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwsz6Mkf.SEED),
      keyType: KeyType.Ed25519,
    })

    didJwsz6MkvKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwsz6Mkv.SEED),
      keyType: KeyType.Ed25519,
    })

    didJwszDnaeyKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwszDnaey.SEED),
      keyType: KeyType.P256,
    })
  })

  afterAll(async () => {
    await wallet.delete()
  })

  it('create and verify a jws with a x509 certificate', async () => {
    const crypto = new Crypto()
    x509.cryptoProvider.set(crypto)

    const alg = {
      name: 'ECDSA',
      namedCurve: 'P-256',
    }

    const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
    const exportedPrivateKey = await crypto.subtle.exportKey('jwk', keys.privateKey)
    const privateKey = TypedArrayEncoder.fromBase64(exportedPrivateKey.d)

    const key = await wallet.createKey({ privateKey, keyType: KeyType.P256 })

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=Test',
      notBefore: new Date('2020/01/01'),
      notAfter: new Date('2020/01/02'),
      signingAlgorithm: alg,
      keys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 2, true),
        new x509.ExtendedKeyUsageExtension(['1.2.3.4.5.6.7', '2.3.4.5.6.7.8'], true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    })

    const payload = { test: 'test' }
    const jws = await jwsService.createJws(agentContext, {
      payload: JsonEncoder.toBuffer(payload),
      key: key,
      header: {},
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.ES256,
        x5c: [cert.toString('base64')],
      },
    })

    const result = await jwsService.verifyJws(agentContext, { jws })
    expect(result.isValid).toBe(true)
    expect(result.jws.payload).toEqual(JsonEncoder.toBase64(payload))
  })

  it('creates and verify a jws using ES256 alg and P-256 kty', async () => {
    const payload = JsonEncoder.toBuffer(didJwszDnaey.DATA_JSON)
    const kid = new DidKey(didJwszDnaeyKey).did

    const jws = await jwsService.createJws(agentContext, {
      payload,
      key: didJwszDnaeyKey,
      header: { kid },
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.ES256,
        jwk: getJwkFromKey(didJwszDnaeyKey),
      },
    })

    expect(jws).toEqual(didJwszDnaey.JWS_JSON)
  })

  it('creates a compact jws', async () => {
    const payload = JsonEncoder.toBuffer(didJwsz6Mkf.DATA_JSON)

    const jws = await jwsService.createJwsCompact(agentContext, {
      payload,
      key: didJwsz6MkfKey,
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.EdDSA,
        jwk: getJwkFromKey(didJwsz6MkfKey),
      },
    })

    expect(jws).toEqual(
      `${didJwsz6Mkf.JWS_JSON.protected}.${TypedArrayEncoder.toBase64URL(payload)}.${didJwsz6Mkf.JWS_JSON.signature}`
    )
  })

  describe('verifyJws', () => {
    it('returns true if the jws signature matches the payload', async () => {
      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        jws: didJwsz6Mkf.JWS_JSON,
      })

      expect(isValid).toBe(true)
      expect(signerKeys).toEqual([didJwsz6MkfKey])
    })

    it('verifies a compact JWS', async () => {
      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        jws: `${didJwsz6Mkf.JWS_JSON.protected}.${didJwsz6Mkf.JWS_JSON.payload}.${didJwsz6Mkf.JWS_JSON.signature}`,
      })

      expect(isValid).toBe(true)
      expect(signerKeys).toEqual([didJwsz6MkfKey])
    })

    it('returns all keys that signed the jws', async () => {
      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        jws: { signatures: [didJwsz6Mkf.JWS_JSON, didJwsz6Mkv.JWS_JSON], payload: didJwsz6Mkf.JWS_JSON.payload },
      })

      expect(isValid).toBe(true)
      expect(signerKeys).toEqual([didJwsz6MkfKey, didJwsz6MkvKey])
    })

    it('returns false if the jws signature does not match the payload', async () => {
      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        jws: {
          ...didJwsz6Mkf.JWS_JSON,
          payload: JsonEncoder.toBase64URL({ ...didJwsz6Mkf, did: 'another_did' }),
        },
      })

      expect(isValid).toBe(false)
      expect(signerKeys).toMatchObject([])
    })

    it('throws an error if the jws signatures array does not contain a JWS', async () => {
      await expect(
        jwsService.verifyJws(agentContext, {
          jws: { signatures: [], payload: '' },
        })
      ).rejects.toThrowError('Unable to verify JWS, no signatures present in JWS.')
    })
  })
})
