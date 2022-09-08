import type { CredDef, Schema } from 'indy-sdk'

import { IndyCredentialUtils } from '../../credentials/formats/indy/IndyCredentialUtils'

export interface LocalResourceRegistry {
  schemas: { [resourceId: string]: SchemaResource }
  credentialDefinitions: { [resourceId: string]: CredentialDefinitionResource }
}

export const resourceRegistry: LocalResourceRegistry = {
  schemas: {},
  credentialDefinitions: {},
}

export type CheqdSchemaResourceData = {
  AnonCredsSchema: {
    attr_names: string[]
    name: string
    version: string
  }
  AnonCredsObjectMetadata: {
    objectFamily: 'anoncreds'
    objectFamilyVersion: 'v2'
    objectType: '2'
    publisherDid: `did:cheqd:testnet:${string}`
    objectURI: `did:cheqd:testnet:${string}/resources/${string}`
  }
}

export interface SchemaResource {
  // The indy data won't be present on the cheqd ledger, but we will have to figure out how this works once we have the cheqd sdk with resources
  // We probably need to resolve the did and find the key in the did document.
  _indyData: {
    did: string
  }
  header: {
    collectionId: string
    id: string
    name: string
    resourceType: 'CL-Schema'
  }
  data: CheqdSchemaResourceData
}

export type CheqdCredDefResourceData = {
  AnonCredsCredDef: Omit<CredDef, 'id'> & { id?: undefined }
  AnonCredsObjectMetadata: {
    objectFamily: 'anoncreds'
    objectFamilyVersion: 'v2'
    objectType: '3'
    publisherDid: `did:cheqd:testnet:${string}`
    objectURI: `did:cheqd:testnet:${string}/resources/${string}`
  }
}

export type CredentialDefinitionResource = {
  // The indy data won't be present on the cheqd ledger, but we will have to figure out how this works once we have the cheqd sdk with resources
  // We probably need to resolve the did and find the key in the did document.
  _indyData: {
    did: string
  }
  header: { collectionId: string; id: string; name: string; resourceType: 'CL-CredDef' }
  data: CheqdCredDefResourceData
}

export function indySchemaFromSchemaResource(schemaResource: SchemaResource): Schema {
  const indySchemaId = indySchemaIdFromSchemaResource(schemaResource)
  const txnId = IndyCredentialUtils.encode(indySchemaId)

  return {
    id: schemaResource.data.AnonCredsObjectMetadata.objectURI,
    attrNames: schemaResource.data.AnonCredsSchema.attr_names,
    name: schemaResource.data.AnonCredsSchema.name,
    seqNo: Number(txnId.substring(0, 6)),
    ver: schemaResource.data.AnonCredsSchema.version,
    version: schemaResource.data.AnonCredsSchema.version,
  }
}

export function cheqdSchemaIdFromSchemaResource(schemaResource: SchemaResource): string {
  return `did:cheqd:testnet:${schemaResource.header.collectionId}/resources/${schemaResource.header.id}`
}

export function cheqdCredentialDefinitionIdFromCredentialDefinitionResource(
  credentialDefinitionResource: CredentialDefinitionResource
): string {
  return `did:cheqd:testnet:${credentialDefinitionResource.header.collectionId}/resources/${credentialDefinitionResource.header.id}`
}

export function indyCredentialDefinitionFromCredentialDefinitionResource(
  credentialDefinitionResource: CredentialDefinitionResource
): CredDef {
  return {
    ...credentialDefinitionResource.data.AnonCredsCredDef,
    id: credentialDefinitionResource.data.AnonCredsObjectMetadata.objectURI,
  }
}

export function indySchemaIdFromSchemaResource(schemaResource: SchemaResource): string {
  const schemaId = `${schemaResource._indyData.did}:2:${schemaResource.header.name}:1.0`

  return schemaId
}
