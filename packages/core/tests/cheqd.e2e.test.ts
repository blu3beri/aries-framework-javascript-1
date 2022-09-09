import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { CredentialStateChangedEvent, ProofStateChangedEvent } from '../src'

import { ReplaySubject, Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import {
  CredentialState,
  Agent,
  CredentialEventTypes,
  LogLevel,
  PresentationPreview,
  PresentationPreviewAttribute,
  PresentationPreviewPredicate,
  PredicateType,
  ProofState,
  ProofEventTypes,
} from '../src'

import { getBaseConfig, waitForCredentialRecordSubject, waitForProofRecordSubject } from './helpers'
import { TestLogger } from './logger'
import { IndyWallet } from '../src/wallet/IndyWallet'

const logger = new TestLogger(LogLevel.debug)

const aliceConfig = getBaseConfig('cheqd alice', {
  logger,
  endpoints: ['rxjs:alice'],
})
const faberConfig = getBaseConfig('cheqd faber', {
  logger,
  endpoints: ['rxjs:faber'],
})

describe('Cheqd', () => {
  test('e2e flow', async () => {
    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:faber': faberMessages,
      'rxjs:alice': aliceMessages,
    }

    const faberAgent = new Agent(faberConfig.config, faberConfig.agentDependencies)
    faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    faberAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    const aliceAgent = new Agent(aliceConfig.config, aliceConfig.agentDependencies)
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    const faberCredentialReplay = new ReplaySubject<CredentialStateChangedEvent>()
    const aliceCredentialReplay = new ReplaySubject<CredentialStateChangedEvent>()
    const faberProofReplay = new ReplaySubject<ProofStateChangedEvent>()
    const aliceProofReplay = new ReplaySubject<ProofStateChangedEvent>()

    faberAgent.events
      .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
      .subscribe(faberCredentialReplay)
    aliceAgent.events
      .observable<CredentialStateChangedEvent>(CredentialEventTypes.CredentialStateChanged)
      .subscribe(aliceCredentialReplay)

    faberAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(faberProofReplay)
    aliceAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(aliceProofReplay)

    const faberWallet = faberAgent.dependencyManager.resolve(IndyWallet)
    const didInfo = await faberWallet.createDid()
    const publicDid = await faberAgent.ledger.registerPublicDid(didInfo.did, didInfo.verkey, 'alias', 'TRUST_ANCHOR')

    expect(publicDid).toMatch(new RegExp('^did:cheqd:testnet:'))

    const resolvedPublicDidData = await faberAgent.ledger.getPublicDid(publicDid)
    expect(resolvedPublicDidData.did).toStrictEqual(publicDid)

    const schema = await faberAgent.ledger.registerSchema({
      attributes: ['name', 'age'],
      name: 'test',
      version: '1.0',
    })

    expect(schema.id.includes('did:cheqd:testnet')).toBe(true)

    const retrievedSchema = await faberAgent.ledger.getSchema(schema.id)
    expect(retrievedSchema).toEqual(schema)

    const credentialDefinition = await faberAgent.ledger.registerCredentialDefinition({
      schema: retrievedSchema,
      supportRevocation: false,
      tag: 'hello',
    })

    expect(credentialDefinition.id.includes('did:cheqd:testnet')).toBe(true)
    const retrievedCredentialDefinition = await faberAgent.ledger.getCredentialDefinition(credentialDefinition.id)

    expect(retrievedCredentialDefinition).toEqual(credentialDefinition)

    const faberOutOfBandRecord = await faberAgent.oob.createInvitation()

    const { connectionRecord: aliceConnectionRecord } = await aliceAgent.oob.receiveInvitation(
      faberOutOfBandRecord.outOfBandInvitation
    )

    if (!aliceConnectionRecord) throw new Error('No connection')

    await aliceAgent.connections.returnWhenIsConnected(aliceConnectionRecord.id)
    const [faberConnection] = await faberAgent.connections.findAllByOutOfBandId(faberOutOfBandRecord.id)

    let faberCredentialRecord = await faberAgent.credentials.offerCredential({
      connectionId: faberConnection.id,
      protocolVersion: 'v2',
      credentialFormats: {
        indy: {
          attributes: [
            {
              name: 'name',
              value: 'Berend',
            },
            {
              name: 'age',
              value: '23',
            },
          ],
          credentialDefinitionId: credentialDefinition.id,
        },
      },
    })

    let aliceCredentialRecord = await waitForCredentialRecordSubject(aliceCredentialReplay, {
      state: CredentialState.OfferReceived,
    })

    await aliceAgent.credentials.acceptOffer({ credentialRecordId: aliceCredentialRecord.id })
    faberCredentialRecord = await waitForCredentialRecordSubject(faberCredentialReplay, {
      state: CredentialState.RequestReceived,
      threadId: faberCredentialRecord.threadId,
    })

    faberCredentialRecord = await faberAgent.credentials.acceptRequest({ credentialRecordId: faberCredentialRecord.id })
    aliceCredentialRecord = await waitForCredentialRecordSubject(aliceCredentialReplay, {
      state: CredentialState.CredentialReceived,
    })

    await aliceAgent.credentials.acceptCredential({ credentialRecordId: aliceCredentialRecord.id })
    await waitForCredentialRecordSubject(faberCredentialReplay, {
      state: CredentialState.Done,
    })

    console.log(await aliceAgent.credentials.getFormatData(aliceCredentialRecord.id))

    //
    // PROOFS
    //

    let aliceProofRecord = await aliceAgent.proofs.proposeProof(
      aliceConnectionRecord.id,
      new PresentationPreview({
        attributes: [
          new PresentationPreviewAttribute({
            name: 'name',
            credentialDefinitionId: credentialDefinition.id,
            value: 'Berend',
          }),
        ],
        predicates: [
          new PresentationPreviewPredicate({
            credentialDefinitionId: credentialDefinition.id,
            name: 'age',
            predicate: PredicateType.GreaterThanOrEqualTo,
            threshold: 18,
          }),
        ],
      })
    )

    let faberProofRecord = await waitForProofRecordSubject(faberProofReplay, {
      state: ProofState.ProposalReceived,
      threadId: aliceProofRecord.threadId,
    })

    faberProofRecord = await faberAgent.proofs.acceptProposal(faberProofRecord.id)

    aliceProofRecord = await waitForProofRecordSubject(aliceProofReplay, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.RequestReceived,
    })

    const requestedCredentials = await aliceAgent.proofs.getRequestedCredentialsForProofRequest(aliceProofRecord.id, {
      filterByNonRevocationRequirements: true,
      filterByPresentationPreview: true,
    })
    const selectedCredentials = aliceAgent.proofs.autoSelectCredentialsForProofRequest(requestedCredentials)
    aliceProofRecord = await aliceAgent.proofs.acceptRequest(aliceProofRecord.id, selectedCredentials)

    faberProofRecord = await waitForProofRecordSubject(faberProofReplay, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.PresentationReceived,
    })
    await faberAgent.proofs.acceptPresentation(faberProofRecord.id)
    aliceProofRecord = await waitForProofRecordSubject(aliceProofReplay, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.Done,
    })

    console.log(aliceProofRecord)

    await faberAgent.wallet.delete()
    await aliceAgent.wallet.delete()
    await faberAgent.shutdown()
    await aliceAgent.shutdown()
  })
})
