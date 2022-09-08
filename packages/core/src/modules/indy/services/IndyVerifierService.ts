import type * as Indy from 'indy-sdk'

import { AgentConfig } from '../../../agent/AgentConfig'
import { IndySdkError } from '../../../error'
import { inject, injectable } from '../../../plugins'
import { isIndyError } from '../../../utils/indyError'
import {
  resourceRegistry,
  indySchemaIdFromSchemaResource,
  indyCredentialDefinitionIdFromCredentialDefinitionResource,
} from '../../ledger/cheqd/cheqdIndyUtils'
import { GenericIndyLedgerService } from '../../ledger/models/IndyLedgerService'

@injectable()
export class IndyVerifierService {
  private indy: typeof Indy
  private ledgerService: GenericIndyLedgerService

  public constructor(
    agentConfig: AgentConfig,
    @inject(GenericIndyLedgerService) ledgerService: GenericIndyLedgerService
  ) {
    this.indy = agentConfig.agentDependencies.indy
    this.ledgerService = ledgerService
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

  public async verifyProof({
    proofRequest,
    proof,
    schemas,
    credentialDefinitions,
  }: VerifyProofOptions): Promise<boolean> {
    try {
      const { revocationRegistryDefinitions, revocationRegistryStates } = await this.getRevocationRegistries(proof)

      const request = this.getIndyProofRequestFromCheqdProofRequest(proofRequest)
      const idMapping: { [id: string]: string } = {}

      const goodSchemas = Object.entries(schemas)
        .map(([schemaId, schema]) => {
          const schemaResource = resourceRegistry.schemas[schemaId]
          if (!schemaResource) throw new Error('no schema found')
          const indySchemaId = indySchemaIdFromSchemaResource(schemaResource)

          idMapping[schemaId] = indySchemaId
          return [indySchemaId, { ...schema, id: indySchemaId }] as const
        })
        .reduce((acc, [schemaId, schema]) => ({ ...acc, [schemaId]: schema }), {})

      const goodCredDefs = Object.entries(credentialDefinitions)
        .map(([credDefId, credDef]) => {
          const credDefResource = resourceRegistry.credentialDefinitions[credDefId]
          if (!credDefResource) throw new Error('no credential definition found')
          const indyCredDefId = indyCredentialDefinitionIdFromCredentialDefinitionResource(credDefResource)

          idMapping[credDefId] = indyCredDefId
          const schemaResource = resourceRegistry.schemas[credDef.schemaId]
          if (!schemaResource) throw new Error('no schema found')
          const schemaId = indySchemaIdFromSchemaResource(schemaResource)
          idMapping[credDef.schemaId] = schemaId

          return [indyCredDefId, { ...credDef, id: indyCredDefId, schemaId }] as const
        })
        .reduce((acc, [schemaId, schema]) => ({ ...acc, [schemaId]: schema }), {})

      const goodProof = {
        ...proof,
        identifiers: proof.identifiers.map((i) => ({
          ...i,
          schema_id: idMapping[i.schema_id],
          cred_def_id: idMapping[i.cred_def_id],
        })),
      }

      return await this.indy.verifierVerifyProof(
        request,
        goodProof,
        goodSchemas,
        goodCredDefs,
        revocationRegistryDefinitions,
        revocationRegistryStates
      )
    } catch (error) {
      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  private async getRevocationRegistries(proof: Indy.IndyProof) {
    const revocationRegistryDefinitions: Indy.RevocRegDefs = {}
    const revocationRegistryStates: Indy.RevStates = Object.create(null)
    for (const identifier of proof.identifiers) {
      const revocationRegistryId = identifier.rev_reg_id
      const timestamp = identifier.timestamp

      //Fetch Revocation Registry Definition if not already fetched
      if (revocationRegistryId && !revocationRegistryDefinitions[revocationRegistryId]) {
        const { revocationRegistryDefinition } = await this.ledgerService.getRevocationRegistryDefinition(
          revocationRegistryId
        )
        revocationRegistryDefinitions[revocationRegistryId] = revocationRegistryDefinition
      }

      //Fetch Revocation Registry by Timestamp if not already fetched
      if (revocationRegistryId && timestamp && !revocationRegistryStates[revocationRegistryId]?.[timestamp]) {
        if (!revocationRegistryStates[revocationRegistryId]) {
          revocationRegistryStates[revocationRegistryId] = Object.create(null)
        }
        const { revocationRegistry } = await this.ledgerService.getRevocationRegistry(revocationRegistryId, timestamp)
        revocationRegistryStates[revocationRegistryId][timestamp] = revocationRegistry
      }
    }
    return { revocationRegistryDefinitions, revocationRegistryStates }
  }
}

export interface VerifyProofOptions {
  proofRequest: Indy.IndyProofRequest
  proof: Indy.IndyProof
  schemas: Indy.Schemas
  credentialDefinitions: Indy.CredentialDefs
}
