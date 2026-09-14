"""Explicit business connection and terminal Outcome acceptance contracts."""
import copy,json,unittest
import test_business_delegation as delegation
from support.business import ACTOR
from authority_delta.business.service import Problem
from services.business.handler import handle

class BusinessConnection(unittest.TestCase):
    def setUp(self):
        self.f=delegation.DelegationFlow();self.f.setUp();self.f.publish()
    def body(self):
        return self.f.command(**{k:self.f.registration[k] for k in
            ('adapter_id','adapter_version','connection_id','registration_hash')},reason='Explicit synthetic test connection')
    def test_registered_does_not_mean_connected_or_authorized(self):
        f=self.f;d=f.app.detail(ACTOR,f.oid)
        self.assertEqual(d['available_adapters'],[])
        with self.assertRaises(Problem) as c:
            f.app.approve_delegation(ACTOR,f.oid,f.command(
                **{k:f.registration[k] for k in ('adapter_id','adapter_version','connection_id')},
                publication_id=d['object']['published_current']['publication_id'],
                publication_digest=d['object']['published_current']['digest'],profile_id='MAINTAIN',reason='test',valid_days=7))
        self.assertEqual(c.exception.code,'OBJECT_CONNECTION_REQUIRED')
        before=copy.deepcopy(d['object']['published_current'])
        body=self.body();out=f.app.connect_adapter(ACTOR,f.oid,body)
        self.assertEqual(f.app.connect_adapter(ACTOR,f.oid,body),out)
        d=f.app.detail(ACTOR,f.oid)
        self.assertEqual(d['object']['published_current'],before)
        self.assertIsNone(d['object']['delegation_approval'])
        self.assertEqual(d['object']['application_status'],'NOT_APPLIED')
        self.assertEqual(len(d['available_adapters']),1)
        self.assertEqual(sum(e['kind']=='EXECUTION_CONNECTION_SELECTED' for e in d['history']),1)
        with self.assertRaises(Problem):f.app.connect_adapter(ACTOR,f.oid,self.body())
    def test_foreign_stale_and_changed_registration_rejected(self):
        for mode in ('foreign','revision','registration'):
            with self.subTest(mode=mode):
                body=self.body();actor=ACTOR
                if mode=='foreign':actor={**ACTOR,'sub':'other'}
                if mode=='revision':body['expected_revision']=0
                if mode=='registration':body['registration_hash']='f'*64
                with self.assertRaises(Problem):self.f.app.connect_adapter(actor,self.f.oid,body)
        self.assertIsNone(self.f.app.detail(ACTOR,self.f.oid)['object'].get('execution_connection'))
    def test_http_contract_enforces_owner_scope_and_schema(self):
        f=self.f;event={'rawPath':'/business/objects/'+f.oid+'/connection','body':json.dumps(self.body()),
            'requestContext':{'http':{'method':'POST'},'authorizer':{'jwt':{'claims':{
                'token_use':'access','client_id':'local','sub':ACTOR['sub'],'scope':'authority-delta/read'}}}}}
        env={'CLIENT_ID':'local','REVIEWER_SUB':ACTOR['sub']}
        self.assertEqual(handle(event,f.app,env)['statusCode'],403)
        event['requestContext']['authorizer']['jwt']['claims']['scope']+=' authority-delta/write'
        self.assertEqual(handle(event,f.app,env)['statusCode'],200)
    def test_pending_or_closed_application_cannot_claim_allow(self):
        f=self.f;start=f.start(f.delegate());target={'kind':'AWS_APPLICATION','id':start['application_id'],'digest':start['enforcement_digest']}
        def record():return f.app.record_outcome(ACTOR,f.oid,f.command(target=target,authority_result='ALLOW',business_result='test result',metrics=[]))
        with self.assertRaises(Problem) as c:record()
        self.assertEqual(c.exception.code,'OUTCOME_APPLICATION_PENDING')
        f.worker(delegation.ScriptedPublisher(publish='RECOVERED_CLOSED')).process(f.message(start))
        with self.assertRaises(Problem) as c:record()
        self.assertEqual(c.exception.code,'OUTCOME_RESULT_INVALID')
