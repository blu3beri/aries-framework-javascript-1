import type { Logger } from '../../../logger'
import type { RequestedCredentials } from '../../proofs'
import type * as Indy from 'indy-sdk'

import { AgentConfig } from '../../../agent/AgentConfig'
import { IndySdkError } from '../../../error/IndySdkError'
import { injectable } from '../../../plugins'
import { isIndyError } from '../../../utils/indyError'
import { IndyWallet } from '../../../wallet/IndyWallet'
import {
  indyCredentialDefinitionIdFromCredentialDefinitionResource,
  indySchemaIdFromSchemaResource,
  resourceRegistry,
} from '../../ledger/cheqd/cheqdIndyUtils'

import { IndyRevocationService } from './IndyRevocationService'

@injectable()
export class IndyHolderService {
  private indy: typeof Indy
  private logger: Logger
  private wallet: IndyWallet
  private indyRevocationService: IndyRevocationService

  public constructor(agentConfig: AgentConfig, indyRevocationService: IndyRevocationService, wallet: IndyWallet) {
    this.indy = agentConfig.agentDependencies.indy
    this.wallet = wallet
    this.indyRevocationService = indyRevocationService
    this.logger = agentConfig.logger
  }

  /**
   * Creates an Indy Proof in response to a proof request. Will create revocation state if the proof request requests proof of non-revocation
   *
   * @param proofRequest a Indy proof request
   * @param requestedCredentials the requested credentials to use for the proof creation
   * @param schemas schemas to use in proof creation
   * @param credentialDefinitions credential definitions to use in proof creation
   * @throws {Error} if there is an error during proof generation or revocation state generation
   * @returns a promise of Indy Proof
   *
   * @todo support attribute non_revoked fields
   */
  public async createProof({
    proofRequest,
    requestedCredentials,
    schemas,
    credentialDefinitions,
  }: CreateProofOptions): Promise<Indy.IndyProof> {
    try {
      this.logger.debug('Creating Indy Proof')

      const request = this.getIndyProofRequestFromCheqdProofRequest(proofRequest)
      const revocationStates: Indy.RevStates = await this.indyRevocationService.createRevocationState(
        request,
        requestedCredentials
      )

      const idMapping: { [key: string]: string } = {}

      const goodSchemas = Object.entries(schemas)
        .map(([schemaId, schema]) => {
          const schemaResource = resourceRegistry.schemas[schemaId]
          if (!schemaResource) throw new Error('no schema found')
          const indySchemaId = indySchemaIdFromSchemaResource(schemaResource)

          idMapping[indySchemaId] = schemaId
          return [indySchemaId, { ...schema, id: indySchemaId }] as const
        })
        .reduce((acc, [schemaId, schema]) => ({ ...acc, [schemaId]: schema }), {})

      const goodCredDefs = Object.entries(credentialDefinitions)
        .map(([credDefId, credDef]) => {
          const credDefResource = resourceRegistry.credentialDefinitions[credDefId]
          if (!credDefResource) throw new Error('no credential definition found')
          const indyCredDefId = indyCredentialDefinitionIdFromCredentialDefinitionResource(credDefResource)

          idMapping[indyCredDefId] = credDefId
          const schemaResource = resourceRegistry.schemas[credDef.schemaId]
          if (!schemaResource) throw new Error('no schema found')
          const schemaId = indySchemaIdFromSchemaResource(schemaResource)
          idMapping[schemaId] = credDef.schemaId

          return [indyCredDefId, { ...credDef, id: indyCredDefId, schemaId }] as const
        })
        .reduce((acc, [schemaId, schema]) => ({ ...acc, [schemaId]: schema }), {})

      const indyProof: Indy.IndyProof = await this.indy.proverCreateProof(
        this.wallet.handle,
        request,
        requestedCredentials.toJSON(),
        this.wallet.masterSecretId,
        goodSchemas,
        goodCredDefs,
        revocationStates
      )

      const proof = {
        ...indyProof,
        identifiers: indyProof.identifiers.map((i) => ({
          ...i,
          schema_id: idMapping[i.schema_id],
          cred_def_id: idMapping[i.cred_def_id],
        })),
      }

      this.logger.trace('Created Indy Proof', {
        indyProof,
      })

      return proof
    } catch (error) {
      this.logger.error(`Error creating Indy Proof`, {
        error,
        proofRequest,
        requestedCredentials,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  /**
   * Store a credential in the wallet.
   *
   * @returns The credential id
   */
  public async storeCredential({
    credentialRequestMetadata,
    credential,
    credentialDefinition,
    credentialId,
    revocationRegistryDefinition,
  }: StoreCredentialOptions): Promise<Indy.CredentialId> {
    const credentialDefinitionResource = resourceRegistry.credentialDefinitions[credentialDefinition.id]
    const schemaResource = resourceRegistry.schemas[credentialDefinition.schemaId]

    if (!credentialDefinitionResource) throw new Error('no credential definition found')
    if (!schemaResource) throw new Error('no credential definition found')

    const credDef: Indy.CredDef = {
      ...credentialDefinition,
      id: indyCredentialDefinitionIdFromCredentialDefinitionResource(credentialDefinitionResource),
      schemaId: indySchemaIdFromSchemaResource(schemaResource),
    }

    const cred: Indy.Cred = {
      ...credential,
      cred_def_id: indyCredentialDefinitionIdFromCredentialDefinitionResource(credentialDefinitionResource),
      schema_id: indySchemaIdFromSchemaResource(schemaResource),
    }

    try {
      return await this.indy.proverStoreCredential(
        this.wallet.handle,
        credentialId ?? null,
        credentialRequestMetadata,
        cred,
        credDef,
        revocationRegistryDefinition ?? null
      )
    } catch (error) {
      this.logger.error(`Error storing Indy Credential '${credentialId}'`, {
        error,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  /**
   * Get a credential stored in the wallet by id.
   *
   * @param credentialId the id (referent) of the credential
   * @throws {Error} if the credential is not found
   * @returns the credential
   *
   * @todo handle record not found
   */
  public async getCredential(credentialId: Indy.CredentialId): Promise<Indy.IndyCredentialInfo> {
    try {
      return await this.indy.proverGetCredential(this.wallet.handle, credentialId)
    } catch (error) {
      this.logger.error(`Error getting Indy Credential '${credentialId}'`, {
        error,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  /**
   * Create a credential request for the given credential offer.
   *
   * @returns The credential request and the credential request metadata
   */
  public async createCredentialRequest({
    holderDid,
    credentialOffer,
    credentialDefinition,
  }: CreateCredentialRequestOptions): Promise<[Indy.CredReq, Indy.CredReqMetadata]> {
    const credentialDefinitionResource = resourceRegistry.credentialDefinitions[credentialDefinition.id]
    const schemaResource = resourceRegistry.schemas[credentialDefinition.schemaId]

    if (!credentialDefinitionResource) throw new Error('no credential definition found')
    if (!schemaResource) throw new Error('no credential definition found')

    const offer: Indy.CredOffer = {
      ...credentialOffer,
      cred_def_id: indyCredentialDefinitionIdFromCredentialDefinitionResource(credentialDefinitionResource),
      schema_id: indySchemaIdFromSchemaResource(schemaResource),
    }

    const credDef: Indy.CredDef = {
      ...credentialDefinition,
      id: indyCredentialDefinitionIdFromCredentialDefinitionResource(credentialDefinitionResource),
      schemaId: indySchemaIdFromSchemaResource(schemaResource),
    }

    try {
      const [request, metadata] = await this.indy.proverCreateCredentialReq(
        this.wallet.handle,
        holderDid,
        offer,
        credDef,
        this.wallet.masterSecretId
      )

      return [
        {
          ...request,
          cred_def_id: credentialDefinition.id,
        },
        metadata,
      ]
    } catch (error) {
      this.logger.error(`Error creating Indy Credential Request`, {
        error,
        credentialOffer,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  private getIndyProofRequestFromCheqdProofRequest(proofRequest: Indy.IndyProofRequest) {
    const requestedAttributes = {} as Indy.IndyProofRequest['requested_attributes']
    const requestedPredicates = {} as Indy.IndyProofRequest['requested_predicates']

    for (const [groupName, requestedAttribute] of Object.entries(proofRequest.requested_attributes)) {
      if (!requestedAttribute.restrictions) {
        requestedAttributes[groupName] = requestedAttribute
        continue
      }

      const restrictions = []

      for (const restriction of requestedAttribute.restrictions) {
        const newRestriction = { ...restriction }

        if (typeof restriction.schema_id === 'string') {
          const schemaResource = resourceRegistry.schemas[restriction.schema_id]
          if (!schemaResource) throw new Error('no schema found')
          newRestriction.schema_id = indySchemaIdFromSchemaResource(schemaResource)
        }

        if (typeof restriction.cred_def_id === 'string') {
          const credDefResource = resourceRegistry.credentialDefinitions[restriction.cred_def_id]
          if (!credDefResource) throw new Error('no cred def found')
          newRestriction.cred_def_id = indyCredentialDefinitionIdFromCredentialDefinitionResource(credDefResource)
        }

        restrictions.push(newRestriction)
      }

      requestedAttributes[groupName] = {
        ...requestedAttribute,
        restrictions,
      }
    }

    for (const [groupName, requestedPredicate] of Object.entries(proofRequest.requested_predicates)) {
      if (!requestedPredicate.restrictions) {
        requestedPredicates[groupName] = requestedPredicate
        continue
      }

      const restrictions = []

      for (const restriction of requestedPredicate.restrictions) {
        const newRestriction = { ...restriction }

        if (typeof restriction.schema_id === 'string') {
          const schemaResource = resourceRegistry.schemas[restriction.schema_id]
          if (!schemaResource) throw new Error('no schema found')
          newRestriction.schema_id = indySchemaIdFromSchemaResource(schemaResource)
        }

        if (typeof restriction.cred_def_id === 'string') {
          const credDefResource = resourceRegistry.credentialDefinitions[restriction.cred_def_id]
          if (!credDefResource) throw new Error('no cred def found')
          newRestriction.cred_def_id = indyCredentialDefinitionIdFromCredentialDefinitionResource(credDefResource)
        }

        restrictions.push(newRestriction)
      }

      requestedPredicates[groupName] = {
        ...requestedPredicate,
        restrictions,
      }
    }

    const request: Indy.IndyProofRequest = {
      ...proofRequest,
      requested_attributes: requestedAttributes,
      requested_predicates: requestedPredicates,
    }

    return request
  }

  /**
   * Retrieve the credentials that are available for an attribute referent in the proof request.
   *
   * @param proofRequest The proof request to retrieve the credentials for
   * @param attributeReferent An attribute referent from the proof request to retrieve the credentials for
   * @param start Starting index
   * @param limit Maximum number of records to return
   *
   * @returns List of credentials that are available for building a proof for the given proof request
   *
   */
  public async getCredentialsForProofRequest({
    proofRequest,
    attributeReferent,
    start = 0,
    limit = 256,
    extraQuery,
  }: GetCredentialForProofRequestOptions): Promise<Indy.IndyCredential[]> {
    const request = this.getIndyProofRequestFromCheqdProofRequest(proofRequest)

    try {
      // Open indy credential search
      const searchHandle = await this.indy.proverSearchCredentialsForProofReq(
        this.wallet.handle,
        request,
        extraQuery ?? null
      )

      try {
        // Make sure database cursors start at 'start' (bit ugly, but no way around in indy)
        if (start > 0) {
          await this.fetchCredentialsForReferent(searchHandle, attributeReferent, start)
        }

        // Fetch the credentials
        const credentials = await this.fetchCredentialsForReferent(searchHandle, attributeReferent, limit)

        const all = {
          ...proofRequest.requested_attributes,
          ...proofRequest.requested_predicates,
        }
        const curr = all[attributeReferent]
        if (!curr.restrictions) {
          throw new Error('Missing restrictions')
        }

        const credDefId = curr.restrictions[0].cred_def_id

        if (typeof credDefId !== 'string') {
          throw new Error('Only cred def filtering supported currently')
        }

        const credDefResource = resourceRegistry.credentialDefinitions[credDefId]
        if (!credDefResource) throw new Error('no cred def found')

        for (const credential of credentials) {
          credential.cred_info.cred_def_id = credDefId
          credential.cred_info.schema_id = credDefResource.data.AnonCredsCredDef.schemaId
        }

        // TODO: sort the credentials (irrevocable first)
        return credentials
      } finally {
        // Always close search
        await this.indy.proverCloseCredentialsSearchForProofReq(searchHandle)
      }
    } catch (error) {
      if (isIndyError(error)) {
        throw new IndySdkError(error)
      }

      throw error
    }
  }

  /**
   * Delete a credential stored in the wallet by id.
   *
   * @param credentialId the id (referent) of the credential
   *
   */
  public async deleteCredential(credentialId: Indy.CredentialId): Promise<void> {
    try {
      return await this.indy.proverDeleteCredential(this.wallet.handle, credentialId)
    } catch (error) {
      this.logger.error(`Error deleting Indy Credential from Wallet`, {
        error,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  private async fetchCredentialsForReferent(searchHandle: number, referent: string, limit?: number) {
    try {
      let credentials: Indy.IndyCredential[] = []

      // Allow max of 256 per fetch operation
      const chunk = limit ? Math.min(256, limit) : 256

      // Loop while limit not reached (or no limit specified)
      while (!limit || credentials.length < limit) {
        // Retrieve credentials
        const credentialsJson = await this.indy.proverFetchCredentialsForProofReq(searchHandle, referent, chunk)
        credentials = [...credentials, ...credentialsJson]

        // If the number of credentials returned is less than chunk
        // It means we reached the end of the iterator (no more credentials)
        if (credentialsJson.length < chunk) {
          return credentials
        }
      }

      return credentials
    } catch (error) {
      this.logger.error(`Error Fetching Indy Credentials For Referent`, {
        error,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }
}

export interface GetCredentialForProofRequestOptions {
  proofRequest: Indy.IndyProofRequest
  attributeReferent: string
  start?: number
  limit?: number
  extraQuery?: Indy.ReferentWalletQuery
}

export interface CreateCredentialRequestOptions {
  holderDid: string
  credentialOffer: Indy.CredOffer
  credentialDefinition: Indy.CredDef
}

export interface StoreCredentialOptions {
  credentialRequestMetadata: Indy.CredReqMetadata
  credential: Indy.Cred
  credentialDefinition: Indy.CredDef
  credentialId?: Indy.CredentialId
  revocationRegistryDefinition?: Indy.RevocRegDef
}

export interface CreateProofOptions {
  proofRequest: Indy.IndyProofRequest
  requestedCredentials: RequestedCredentials
  schemas: Indy.Schemas
  credentialDefinitions: Indy.CredentialDefs
}
