import type { SchemaResource, CredentialDefinitionResource, LocalResourceRegistry } from '../cheqd/cheqdIndyUtils'

import { injectable } from 'tsyringe'

import { AriesFrameworkError } from '../../../error'
import { IndyCredentialUtils } from '../../credentials/formats/indy/IndyCredentialUtils'
import { resourceRegistry, indySchemaIdFromSchemaResource } from '../cheqd/cheqdIndyUtils'

@injectable()
export class CheqdResourceService {
  private resourceRegistry: LocalResourceRegistry = {
    schemas: {},
    credentialDefinitions: {},
  }

  // TODO-CHEQD: integrate with cheqd-sdk
  public async getSchemaResource(schemaId: string): Promise<SchemaResource> {
    const resource = resourceRegistry.schemas[schemaId]

    if (!resource) {
      throw new AriesFrameworkError(`Schema with id ${schemaId} not found`)
    }

    return resource
  }

  // TODO-CHEQD: integrate with cheqd sdk
  public async getCredentialDefinitionResource(credentialDefinitionId: string): Promise<CredentialDefinitionResource> {
    const resource = resourceRegistry.credentialDefinitions[credentialDefinitionId]

    if (!resource) {
      throw new AriesFrameworkError(`Credential definition with id ${credentialDefinitionId} not found`)
    }

    return resource
  }

  public async indyCredentialDefinitionIdFromCheqdCredentialDefinitionId(cheqdCredDefId: string) {
    const credDefResource = await this.getCredentialDefinitionResource(cheqdCredDefId)
    const schemaResource = await this.getSchemaResource(credDefResource.data.AnonCredsCredDef.schemaId)

    const schemaId = indySchemaIdFromSchemaResource(schemaResource)
    const txnId = IndyCredentialUtils.encode(schemaId).substring(0, 6)

    const credentialDefinitionId = `${credDefResource._indyData.did}:3:CL:${txnId}:${credDefResource.data.AnonCredsCredDef.tag}`
    return credentialDefinitionId
  }

  public async indySchemaIdFromCheqdSchemaId(cheqdSchemaId: string) {
    const schemaResource = await this.getSchemaResource(cheqdSchemaId)
    const schemaId = indySchemaIdFromSchemaResource(schemaResource)
    return schemaId
  }
}
