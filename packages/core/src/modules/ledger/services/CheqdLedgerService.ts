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
import type { DidStdFee } from '@cheqd/sdk/build/types'
import type { TImportableEd25519Key } from '@cheqd/sdk/build/utils'
import type { MsgCreateDidPayload, MsgUpdateDidPayload } from '@cheqd/ts-proto/cheqd/v1/tx'
import type Indy from 'indy-sdk'

import { DIDModule, createCheqdSDK } from '@cheqd/sdk'
import { createSignInputsFromImportableEd25519Key } from '@cheqd/sdk/build/utils'
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing'

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

@injectable()
export class CheqdLedgerService implements GenericIndyLedgerService {
  private wallet: IndyWallet
  private indy: typeof Indy
  private cheqdResourceService: CheqdResourceService

  private sdk?: CheqdSDK
  private fee?: DidStdFee

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

    return did as string
  }

  // TODO-CHEQD: I don't think we would need to manually, if at all, deal with pools
  public connectToPools(): Promise<number[]> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public async registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: Indy.NymRole
  ): Promise<string> {
    // TODO-CHEQD: create/get a keypair from wallet
    const key: TImportableEd25519Key = { type: 'Ed25519', privateKeyHex: '0xa', kid: 'kid', publicKeyHex: '0xa' }
    const sdk = await this.getCheqdSDK()
    const identifier = await this.createIdentifier(
      { options: { document: { id: targetDid, alsoKnownAs: [alias] }, keys: [key] } },
      { sdk }
    )

    return identifier
  }

  // TODO-CHEQD: implement
  public getPublicDid(did: string): Promise<Indy.GetNymResponse> {
    throw new Error('Method not implemented.')
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

    return indySchemaFromSchemaResource(resource)
  }

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

    console.log(credDefId)

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
