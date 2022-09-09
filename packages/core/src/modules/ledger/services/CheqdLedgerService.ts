/* eslint-disable no-console */
import type { Logger } from '../../../logger'
import type { CredentialDefinitionResource, SchemaResource } from '../cheqd/cheqdIndyUtils'
import type { GenericIndyLedgerService } from '../models/IndyLedgerService'
import type {
  IndyEndpointAttrib,
  SchemaTemplate,
  CredentialDefinitionTemplate,
  ParseRevocationRegistryDefinitionTemplate,
  ParseRevocationRegistryDeltaTemplate,
  ParseRevocationRegistryTemplate,
} from './IndyLedgerService'
import type { CheqdSDK, ICheqdSDKOptions } from '@cheqd/sdk'
import type { AbstractCheqdSDKModule } from '@cheqd/sdk/build/modules/_'
import type { DidStdFee, IContext, IKeyPair } from '@cheqd/sdk/build/types'
import type { TImportableEd25519Key } from '@cheqd/sdk/build/utils'
import type { MsgUpdateDidPayload, SignInfo, MsgCreateDidPayload } from '@cheqd/ts-proto/cheqd/v1/tx'
import type { MsgCreateResource } from '@cheqd/ts-proto/resource/v1/tx'
import type { DeliverTxResponse } from '@cosmjs/stargate'
import type { DIDDocument } from 'did-resolver'
import type Indy from 'indy-sdk'

import { agentDependencies } from '@aries-framework/node'
import { DIDModule, createCheqdSDK } from '@cheqd/sdk'
import { MethodSpecificIdAlgo, VerificationMethods } from '@cheqd/sdk/build/types'
import {
  createDidPayload,
  createDidVerificationMethod,
  createKeyPairBase64,
  createVerificationKeys,
  createSignInputsFromImportableEd25519Key,
} from '@cheqd/sdk/build/utils'
import { MsgCreateResourcePayload } from '@cheqd/ts-proto/resource/v1/tx'
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing'
import { base64ToBytes, EdDSASigner, ES256KSigner, ES256Signer, hexToBytes } from 'did-jwt'
import { Writer } from 'protobufjs'
import { fromString, toString } from 'uint8arrays'
import { TextEncoder } from 'util'

import { AgentConfig } from '../../../agent/AgentConfig'
import { KeyType } from '../../../crypto'
import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { TypedArrayEncoder } from '../../../utils'
import { uuid } from '../../../utils/uuid'
import { IndyWallet } from '../../../wallet/IndyWallet'
import { DidDoc } from '../../connections'
import { Key } from '../../dids'
import { didDocumentToNumAlgo2Did } from '../../dids/methods/peer/peerDidNumAlgo2'
import {
  indyCredentialDefinitionFromCredentialDefinitionResource,
  indySchemaFromSchemaResource,
  resourceRegistry,
} from '../cheqd/cheqdIndyUtils'

import { CheqdResourceService } from './CheqdResourceService'

// --------------

const assert = (b: boolean, msg: string) => {
  if (b) return

  throw new AriesFrameworkError(msg)
}

export type IdentifierPayload = Partial<MsgCreateDidPayload> | Partial<MsgUpdateDidPayload>

const clog = (...args: any[]) => {
  console.log('---------------------- LOG ------------------------')
  console.log(args)
  console.log('---------------------- LOG ------------------------')
}

// --------------

export interface ISignInputs {
  verificationMethodId: string
  keyType?: 'Ed25519' | 'Secp256k1' | 'P256'
  privateKeyHex: string
}
export const faucet = {
  prefix: 'cheqd',
  minimalDenom: 'ncheq',
  mnemonic:
    'sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright',
  address: 'cheqd1rnr5jrt4exl0samwj0yegv99jeskl0hsxmcz96',
}

@injectable()
export class CheqdLedgerService implements GenericIndyLedgerService {
  private wallet: IndyWallet
  private indy: typeof Indy
  private cheqdResourceService: CheqdResourceService
  private logger: Logger
  private config: AgentConfig

  private sdk?: CheqdSDK
  private fee?: DidStdFee

  private cheqdKeyPair?: IKeyPair

  public constructor(wallet: IndyWallet, agentConfig: AgentConfig, cheqdResourceService: CheqdResourceService) {
    this.wallet = wallet
    this.indy = agentConfig.agentDependencies.indy
    this.cheqdResourceService = cheqdResourceService
    this.logger = agentConfig.logger
    this.config = agentConfig
  }

  private async getCheqdSDK(fee?: DidStdFee): Promise<CheqdSDK> {
    const RPC_URL = 'https://rpc.cheqd.network'
    const COSMOS_PAYER_WALLET = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic, { prefix: faucet.prefix })

    if (this.sdk) return this.sdk

    const sdkOptions: ICheqdSDKOptions = {
      modules: [DIDModule as unknown as AbstractCheqdSDKModule],
      rpcUrl: RPC_URL,
      wallet: COSMOS_PAYER_WALLET,
    }

    this.sdk = await createCheqdSDK(sdkOptions)
    this.fee = fee || {
      amount: [
        {
          denom: faucet.minimalDenom,
          amount: '5000000',
        },
      ],
      gas: '200000',
      payer: (await sdkOptions.wallet.getAccounts())[0].address,
    }
    return this.sdk
  }

  public async registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: Indy.NymRole,
    fee?: DidStdFee
  ): Promise<string> {
    const seed = this.config.publicDidSeed
    assert(seed ? seed.length > 0 : false, 'NO SEED PROVIDED IN THE AGENT CONFIG')
    // TODO-CHEQD: create/get a keypair from wallet
    const cheqdKeyPair = createKeyPairBase64()
    this.cheqdKeyPair = cheqdKeyPair

    const indyKeyPair: IKeyPair = {
      publicKey: TypedArrayEncoder.toBase64(TypedArrayEncoder.fromBase58(verkey)),
      privateKey: ':)',
    }

    const indyVerificationKey = createVerificationKeys(indyKeyPair, MethodSpecificIdAlgo.Base58, 'indykey-1')
    const cheqdVerificationKey = createVerificationKeys(cheqdKeyPair, MethodSpecificIdAlgo.Base58, 'key-2')
    const verificationKeys = [indyVerificationKey]

    const verificationMethods = createDidVerificationMethod(
      [VerificationMethods.Base58, VerificationMethods.Base58],
      [indyVerificationKey, cheqdVerificationKey]
    ).map((m) => {
      m.id = indyVerificationKey.didUrl + '#' + m.id.split('#')[1]
      m.controller = indyVerificationKey.didUrl
      return m
    })

    const didPayload = createDidPayload(verificationMethods, verificationKeys)
    console.log(JSON.stringify(didPayload))

    // Use the cheqd keypair for sining
    const privateKeyHex = toString(fromString(cheqdKeyPair.privateKey, 'base64'), 'hex')
    const publicKeyHex = toString(fromString(cheqdKeyPair.publicKey, 'base64'), 'hex')

    const key: TImportableEd25519Key = {
      type: 'Ed25519',
      privateKeyHex: privateKeyHex,
      kid: 'kid',
      publicKeyHex: publicKeyHex,
    }

    const signInputs = [key].map((k) => createSignInputsFromImportableEd25519Key(k, [verificationMethods[1]]))

    const sdk = await this.getCheqdSDK()

    const resp = await sdk.createDidTx(signInputs, didPayload, faucet.address, this.fee || 'auto', undefined, { sdk })
    assert(resp.code === 0, `Could not register did! Response ${JSON.stringify(resp)}`)

    return didPayload.id
  }

  // TODO-CHEQD: implement
  public async getPublicDid(did: string): Promise<Indy.GetNymResponse> {
    const didDoc: DIDDocument = (
      await (await agentDependencies.fetch(`https://dev.uniresolver.io/1.0/identifiers/${did}`)).json()
    ).didDocument
    const data = (didDoc.verificationMethod ?? []).find((v) => v.id.endsWith('indykey-1'))
    if (!data) throw new AriesFrameworkError('NO indykey-1 FOUND IN THE VERIFICATION METHODS')
    const verkey = data.publicKeyMultibase
    if (!verkey) throw new AriesFrameworkError('NO publicKeyMultibase FOUND IN THE VERIFICATION METHODS')

    return {
      did: data.id.replace('#indykey-1', ''),
      verkey,
      // MOCK ROLE
      role: 'TRUSTEE',
    }
  }

  // TODO-CHEQD: integrate with cheqd-sdk
  public async registerSchema(indyDid: string, schemaTemplate: SchemaTemplate): Promise<Indy.Schema> {
    // This part transform the indy did into the cheqd did in a hacky way. In the future we should pass the cheqd did directly,
    // But that requires better integration with the did module
    // Get the verkey for the provided indy did
    const verkey = await this.indy.keyForLocalDid(this.wallet.handle, indyDid)
    const cheqdDidIdentifier = Key.fromPublicKeyBase58(verkey, KeyType.Ed25519).fingerprint.substring(0, 32)

    const resourceId = uuid()
    const resource: SchemaResource = {
      _indyData: {
        did: indyDid,
      },
      header: {
        collectionId: cheqdDidIdentifier,
        id: resourceId,
        name: schemaTemplate.name,
        resourceType: 'CL-Schema',
      },
      data: {
        AnonCredsSchema: {
          attr_names: schemaTemplate.attributes,
          name: schemaTemplate.name,
          version: schemaTemplate.version,
        },
        AnonCredsObjectMetadata: {
          objectFamily: 'anoncreds',
          objectFamilyVersion: 'v2',
          objectType: '2',
          objectURI: `did:cheqd:testnet:${cheqdDidIdentifier}/resources/${resourceId}`,
          publisherDid: `did:cheqd:testnet:${cheqdDidIdentifier}`,
        },
      },
    } as const

    // Register schema in local registry
    resourceRegistry.schemas[resource.data.AnonCredsObjectMetadata.objectURI] = resource

    console.log(this.verificationMethods)

    if (!this.verificationMethods) throw new AriesFrameworkError('Missing verification methods')
    if (!this.verificationKeys) throw new AriesFrameworkError('Missing verification keys')

    const didPayload = createDidPayload(this.verificationMethods, [this.verificationKeys])
    const resourcePayload: MsgCreateResourcePayload = {
      collectionId: didPayload.id.split(':').reverse()[0],
      id: resourceId,
      name: `Cheqd Schema ${uuid}`,
      resourceType: 'Cheqd Schema',
      data: new TextEncoder().encode(JSON.stringify(resource.data)),
    }
    await this.writeTxResource(resourceId, resourcePayload)

    return indySchemaFromSchemaResource(resource)
  }

  private async writeTxResource(resourceId: string, resourcePayload: MsgCreateResourcePayload) {
    if (!this.verificationMethods) throw new AriesFrameworkError('Missing verification methods')
    if (!this.verificationKeys) throw new AriesFrameworkError('Missing verification keys')
    if (!this.cheqdKeyPair) throw new AriesFrameworkError('Missing verification keys')

    const didPayload = createDidPayload(this.verificationMethods, [this.verificationKeys])

    this.logger.warn(`Using payload: ${JSON.stringify(resourcePayload)}`)

    const sdk = await this.getCheqdSDK()
    const resourceSignInputs: ISignInputs[] = [
      {
        verificationMethodId: didPayload.verificationMethod[0].id,
        keyType: 'Ed25519',
        privateKeyHex: toString(fromString(this.cheqdKeyPair.privateKey, 'base64'), 'hex'),
      },
    ]

    const resourceTx = await this.createResourceTx(
      resourceSignInputs,
      resourcePayload,
      (
        await sdk.options.wallet.getAccounts()
      )[0].address,
      this.fee ?? {
        amount: [
          {
            denom: 'ncheq',
            amount: '5000000',
          },
        ],
        gas: '200000',
        payer: (await sdk.options.wallet.getAccounts())[0].address,
      }
    )

    this.logger.warn(`Resource Tx: ${JSON.stringify(resourceTx)}`)

    assert(resourceTx.code === 0, `ResourceTx not written. Exit data ${JSON.stringify(resourceTx)}`)

    return resourceTx
  }

  public async createResourceTx(
    signInputs: ISignInputs[],
    resourcePayload: Partial<MsgCreateResourcePayload>,
    address: string,
    fee: DidStdFee | 'auto' | number,
    memo?: string,
    context?: IContext
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getCheqdSDK()
    const signer = sdk.signer

    const payload = MsgCreateResourcePayload.fromPartial(resourcePayload)

    const msg = await this.signPayload(payload, signInputs)

    const typeUrlMsgCreateResource = `/${protobufPackage}.MsgCreateResource`
    const encObj = {
      typeUrl: typeUrlMsgCreateResource,
      value: msg,
    }

    return signer.signAndBroadcast(address, [encObj], fee, memo)
  }

  private async signPayload(payload: MsgCreateResourcePayload, signInputs: ISignInputs[]): Promise<MsgCreateResource> {
    const signBytes = this.getMsgCreateResourcePayloadAminoSignBytes(payload)
    const signatures = await this.signIdentityTx(signBytes, signInputs)

    return {
      payload,
      signatures,
    }
  }

  private async signIdentityTx(signBytes: Uint8Array, signInputs: ISignInputs[]): Promise<SignInfo[]> {
    const signInfos: SignInfo[] = []

    for (const signInput of signInputs) {
      if (typeof signInput.keyType === undefined) {
        throw new Error('Key type is not defined')
      }

      let signature: string

      switch (signInput.keyType) {
        case 'Ed25519':
          signature = (await EdDSASigner(hexToBytes(signInput.privateKeyHex))(signBytes)) as string
          break
        case 'Secp256k1':
          signature = (await ES256KSigner(hexToBytes(signInput.privateKeyHex))(signBytes)) as string
          break
        case 'P256':
          signature = (await ES256Signer(hexToBytes(signInput.privateKeyHex))(signBytes)) as string
          break
        default:
          throw new Error(`Unsupported signature type: ${signInput.keyType}`)
      }

      signInfos.push({
        verificationMethodId: signInput.verificationMethodId,
        signature: toString(base64ToBytes(signature), 'base64pad'),
      })
    }

    return signInfos
  }

  private getMsgCreateResourcePayloadAminoSignBytes(message: MsgCreateResourcePayload): Uint8Array {
    const writer = new Writer()

    if (message.collectionId !== '') {
      writer.uint32(10).string(message.collectionId)
    }
    if (message.id !== '') {
      writer.uint32(18).string(message.id)
    }
    if (message.name !== '') {
      writer.uint32(26).string(message.name)
    }
    if (message.resourceType !== '') {
      writer.uint32(34).string(message.resourceType)
    }
    if (message.data.length !== 0) {
      // Animo coded assigns index 5 to this property. In proto definitions it's 6.
      // Since we use amino on node + non default property indexing, we need to encode it manually.
      writer.uint32(42).bytes(message.data)
    }

    return writer.finish()
  }

  // TODO-CHEQD: integrate with cheqd-sdk
  //public async getSchema(schemaId: string): Promise<Indy.Schema> {
  //  const resource = await this.cheqdResourceService.getSchemaResource(schemaId)

  //private getMsgCreateResourcePayloadAminoSignBytes(message: MsgCreateResourcePayload): Uint8Array {
  //  const writer = new Writer()

  //  if (message.collectionId !== '') {
  //    writer.uint32(10).string(message.collectionId)
  //  }
  //  if (message.id !== '') {
  //    writer.uint32(18).string(message.id)
  //  }
  //  if (message.name !== '') {
  //    writer.uint32(26).string(message.name)
  //  }
  //  if (message.resourceType !== '') {
  //    writer.uint32(34).string(message.resourceType)
  //  }
  //  if (message.data.length !== 0) {
  //    // Animo coded assigns index 5 to this property. In proto definitions it's 6.
  //    // Since we use amino on node + non default property indexing, we need to encode it manually.
  //    writer.uint32(42).bytes(message.data)
  //  }

  //  return writer.finish()
  //}

  // TODO-CHEQD: integrate with cheqd-sdk
  public async getSchema(schemaId: string): Promise<Indy.Schema> {
    const resource = await this.cheqdResourceService.getSchemaResource(schemaId)

    return indySchemaFromSchemaResource(resource)
  }

  // TODO-CHEQD: integrate with cheqd sdk
  public async registerCredentialDefinition(
    indyDid: string,
    credentialDefinitionTemplate: CredentialDefinitionTemplate
  ): Promise<Indy.CredDef> {
    const { schema, tag, signatureType, supportRevocation } = credentialDefinitionTemplate

    // This part transform the indy did into the cheqd did in a hacky way. In the future we should pass the cheqd did directly,
    // But that requires better integration with the did module
    // Get the verkey for the provided indy did
    const verkey = await this.indy.keyForLocalDid(this.wallet.handle, indyDid)
    const cheqdDidIdentifier = Key.fromPublicKeyBase58(verkey, KeyType.Ed25519).fingerprint.substring(0, 32)

    const indySchemaId = await this.cheqdResourceService.indySchemaIdFromCheqdSchemaId(schema.id)

    const indySchema: Indy.Schema = {
      ...schema,
      id: indySchemaId,
    }

    const [credDefId, credentialDefinition] = await this.indy.issuerCreateAndStoreCredentialDef(
      this.wallet.handle,
      indyDid,
      indySchema,
      tag,
      signatureType,
      {
        support_revocation: supportRevocation,
      }
    )

    this.logger.info(credDefId)

    const resourceId = uuid()

    const resource: CredentialDefinitionResource = {
      _indyData: {
        did: indyDid,
      },
      header: {
        collectionId: cheqdDidIdentifier,
        id: resourceId,
        name: tag,
        resourceType: 'CL-CredDef',
      },
      data: {
        AnonCredsCredDef: { ...credentialDefinition, id: undefined, schemaId: schema.id },
        AnonCredsObjectMetadata: {
          objectFamily: 'anoncreds',
          objectFamilyVersion: 'v2',
          objectType: '3',
          objectURI: `did:cheqd:testnet:${cheqdDidIdentifier}/resources/${resourceId}`,
          publisherDid: `did:cheqd:testnet:${cheqdDidIdentifier}`,
        },
      },
    } as const

    resourceRegistry.credentialDefinitions[resource.data.AnonCredsObjectMetadata.objectURI] = resource

    if (!this.verificationMethods) throw new AriesFrameworkError('Missing verification methods')
    if (!this.verificationKeys) throw new AriesFrameworkError('Missing verification keys')

    const didPayload = createDidPayload(this.verificationMethods, [this.verificationKeys])
    const resourcePayload: MsgCreateResourcePayload = {
      collectionId: didPayload.id.split(':').reverse()[0],
      id: resourceId,
      name: `Cheqd Credential Definition ${uuid}`,
      resourceType: 'cheqd-credential-definition',
      data: new TextEncoder().encode(JSON.stringify(resource.data)),
    }
    await this.writeTxResource(resourceId, resourcePayload)

    return indyCredentialDefinitionFromCredentialDefinitionResource(resource)
  }

  public async getCredentialDefinition(credentialDefinitionId: string): Promise<Indy.CredDef> {
    const resource = await this.cheqdResourceService.getCredentialDefinitionResource(credentialDefinitionId)

    return indyCredentialDefinitionFromCredentialDefinitionResource(resource)
  }

  public getRevocationRegistryDefinition(): Promise<ParseRevocationRegistryDefinitionTemplate> {
    throw new Error('Method not implemented.')
  }

  public getEndpointsForDid(): Promise<IndyEndpointAttrib> {
    throw new Error('Method not implemented.')
  }

  public getRevocationRegistryDelta(): Promise<ParseRevocationRegistryDeltaTemplate> {
    throw new Error('Method not implemented.')
  }

  public getRevocationRegistry(): Promise<ParseRevocationRegistryTemplate> {
    throw new Error('Method not implemented.')
  }

  public connectToPools(): Promise<number[]> {
    throw new Error('Method not implemented.')
  }
}
