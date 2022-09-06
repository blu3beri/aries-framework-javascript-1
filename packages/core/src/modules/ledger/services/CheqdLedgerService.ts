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
import type { MsgCreateDidEncodeObject } from '@cheqd/sdk/build/modules/did'
import type { DidStdFee, IContext, IKeyPair, IVerificationKeys } from '@cheqd/sdk/build/types'
import type { TImportableEd25519Key } from '@cheqd/sdk/build/utils'
import type { VerificationMethod } from '@cheqd/ts-proto/cheqd/v1/did'
import type { MsgUpdateDidPayload, MsgCreateDid, SignInfo } from '@cheqd/ts-proto/cheqd/v1/tx'
import type { MsgCreateResource } from '@cheqd/ts-proto/resource/v1/tx'
import type { DeliverTxResponse } from '@cosmjs/stargate'
import type Indy from 'indy-sdk'

import { DIDModule, createCheqdSDK } from '@cheqd/sdk'
import { MethodSpecificIdAlgo, VerificationMethods } from '@cheqd/sdk/build/types'
import {
  createDidPayload,
  createDidVerificationMethod,
  createKeyPairBase64,
  createVerificationKeys,
  createSignInputsFromImportableEd25519Key,
} from '@cheqd/sdk/build/utils'
import { protobufPackage, MsgCreateDidPayload } from '@cheqd/ts-proto/cheqd/v1/tx'
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
import { uuid } from '../../../utils/uuid'
import { IndyWallet } from '../../../wallet/IndyWallet'
import { Key } from '../../dids'
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

// --------------

export interface ISignInputs {
  verificationMethodId: string
  keyType?: 'Ed25519' | 'Secp256k1' | 'P256'
  privateKeyHex: string
}

@injectable()
export class CheqdLedgerService implements GenericIndyLedgerService {
  private wallet: IndyWallet
  private indy: typeof Indy
  private cheqdResourceService: CheqdResourceService

  private sdk?: CheqdSDK
  private fee?: DidStdFee
  private cheqdDid?: string
  private verificationMethods?: VerificationMethod[]
  private verificationKeys?: IVerificationKeys
  private keyPair?: IKeyPair

  public constructor(wallet: IndyWallet, agentConfig: AgentConfig, cheqdResourceService: CheqdResourceService) {
    this.wallet = wallet
    this.indy = agentConfig.agentDependencies.indy
    this.cheqdResourceService = cheqdResourceService
  }

  private async getCheqdSDK(fee?: DidStdFee): Promise<CheqdSDK> {
    const COSMOS_PAYER_MNEMONIC = 'TODO-CHEQD'
    const RPC_URL = 'https://rpc.cheqd.network'
    const COSMOS_PAYER_WALLET = await DirectSecp256k1HdWallet.fromMnemonic(COSMOS_PAYER_MNEMONIC, { prefix: 'cheqd' })

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
          denom: 'ncheq',
          amount: '5000000',
        },
      ],
      gas: '200000',
      payer: (await sdkOptions.wallet.getAccounts())[0].address,
    }
    return this.sdk
  }

  /**
   * https://github.com/cheqd/did-provider-cheqd/blob/7698f320ead5d9b4e278ac13cd9319dd5115cb83/src/did-manager/cheqd-did-provider.ts#L95
   */
  private async createIdentifier({
    options,
  }: {
    alias?: string
    options: { document: IdentifierPayload; keys: TImportableEd25519Key[] }
  }): Promise<string> {
    const sdk = await this.getCheqdSDK()

    const signInputs = options.keys.map((key) =>
      createSignInputsFromImportableEd25519Key(key, options.document.verificationMethod ?? [])
    )

    const tx = await sdk.createDidTx(signInputs, options.document, '', this.fee || 'auto', undefined, { sdk })

    assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`)

    // TODO-CHEQD: this will just use the `targetDid` as supplied in the registerPublicDid function
    // Is this correct?
    const did = options.document.id

    this.cheqdDid = did
    return did as string
  }

  // TODO-CHEQD: I don't think we would need to manually, if at all, deal with pools
  public connectToPools(): Promise<number[]> {
    throw new Error('Method not implemented.')
  }

  public async createDidTx(
    signInputs: ISignInputs[],
    didPayload: Partial<MsgCreateDidPayload>,
    address: string,
    fee: DidStdFee | 'auto' | number,
    memo?: string,
    context?: IContext
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getCheqdSDK()
    const signer = sdk.signer

    const payload = MsgCreateDidPayload.fromPartial(didPayload)
    const signatures = await signer.signCreateDidTx(signInputs, payload)

    const value: MsgCreateDid = {
      payload,
      signatures,
    }

    const typeUrlMsgCreateDid = `/${protobufPackage}.MsgCreateDid`
    const createDidMsg: MsgCreateDidEncodeObject = {
      typeUrl: typeUrlMsgCreateDid,
      value,
    }

    return signer.signAndBroadcast(address, [createDidMsg], fee, memo)
  }

  // TODO-CHEQD: implement
  public async registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: Indy.NymRole,
    fee?: DidStdFee
  ): Promise<string> {
    // TODO-CHEQD: create/get a keypair from wallet
    const keyPair = createKeyPairBase64()
    this.keyPair = keyPair
    const verificationKeys = createVerificationKeys(keyPair, MethodSpecificIdAlgo.Base58, 'key-1', 16)
    this.verificationKeys = verificationKeys
    const verificationMethods = createDidVerificationMethod([VerificationMethods.Base58], [verificationKeys])
    this.verificationMethods
      ? this.verificationMethods.push(...verificationMethods)
      : (this.verificationMethods = verificationMethods)
    const didPayload = createDidPayload(verificationMethods, [verificationKeys])
    const privateKeyHex = toString(fromString(keyPair.privateKey, 'base64'), 'hex')
    const publicKeyHex = toString(fromString(keyPair.publicKey, 'base64'), 'hex')
    const key: TImportableEd25519Key = {
      type: 'Ed25519',
      privateKeyHex: privateKeyHex,
      kid: 'kid',
      publicKeyHex: publicKeyHex,
    }

    const signInputs: ISignInputs[] = [
      {
        verificationMethodId: didPayload.verificationMethod[0].id,
        keyType: 'Ed25519',
        privateKeyHex: privateKeyHex,
      },
    ]

    const sdk = await this.getCheqdSDK()

    const didTx: DeliverTxResponse = await this.createDidTx(
      signInputs,
      didPayload,
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

    this.logger.warn(`Using payload: ${JSON.stringify(didPayload)}`)
    this.logger.warn(`DID Tx: ${JSON.stringify(didTx)}`)

    const identifier = this.createIdentifier({
      options: { document: { id: targetDid, alsoKnownAs: [alias] }, keys: [key] },
    })
    return identifier
  }

  // TODO-CHEQD: implement
  public async getPublicDid(): Promise<Indy.GetNymResponse> {
    const sdk = await this.getCheqdSDK()
    const verkey = (await sdk.options.wallet.getAccounts())[0].pubkey
    if (!this.cheqdDid) {
      throw new AriesFrameworkError('No did available')
    } else {
      const getNymResponse: Indy.GetNymResponse = {
        did: this.cheqdDid,
        verkey: verkey[0].toString(), // TODO: is this really the verkey?
        role: 'TRUSTEE', // TODO: What is the role? Where to get the correct role from?
      }
      return getNymResponse
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
    if (!this.keyPair) throw new AriesFrameworkError('Missing verification keys')

    const didPayload = createDidPayload(this.verificationMethods, [this.verificationKeys])

    this.logger.warn(`Using payload: ${JSON.stringify(resourcePayload)}`)

    const sdk = await this.getCheqdSDK()
    const resourceSignInputs: ISignInputs[] = [
      {
        verificationMethodId: didPayload.verificationMethod[0].id,
        keyType: 'Ed25519',
        privateKeyHex: toString(fromString(this.keyPair.privateKey, 'base64'), 'hex'),
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

    assert(resourceTx.code === 0, 'ResourceTx not written. Exit code unequal to 0')

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
  public async getSchema(schemaId: string): Promise<Indy.Schema> {
    const resource = resourceRegistry.schemas[schemaId]

    if (!resource) {
      throw new AriesFrameworkError(`Schema with id ${schemaId} not found`)
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
}
