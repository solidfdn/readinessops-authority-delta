"""Recovery uses one pinned synthetic job without duplicating its model attempt."""
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch

import deploy_business as deployment
from authority_delta.business.storage import Row, encode
from authority_delta.canonical import sha256_json
from support.business import MemoryBlobs, MemoryStore, observed


class CanaryRecovery(unittest.TestCase):
    def setUp(self):
        self.db=MemoryStore();self.blobs=MemoryBlobs()
        self.source=deployment.canary_input(deployment.CANARY_RECOVERY_RUN)
        self.raw=encode(self.source)
        self.ref=dict(deployment.CANARY_RECOVERY_INPUT,sha256=hashlib.sha256(self.raw).hexdigest(),size=len(self.raw))
        self.blobs.data[(self.ref['key'],self.ref['version_id'])]=self.raw
        self.resources={'DataBucket':self.ref['bucket'],'JobsTable':'retained-jobs','AppTable':'retained-app',
                        'Queue':'retained-queue','AnalysisRuntimeArn':'retained-runtime','AnalysisRuntimeVersion':'2'}
        pin=deployment.CANARY_RECOVERY_REPORT
        self.prior={'scope':deployment.SCOPE,'build_id':pin['build_id'],'source_sha256':pin['source_sha256'],
                    'account':deployment.ACCOUNT,'region':deployment.REGION,'result':'FAIL','state_unchanged':True,
                    'approval_recorded':False,'business_resources':dict(self.resources,AnalysisRuntimeVersion='1'),
                    'business_canary':{'scope':'SYNTHETIC_NONPAYMENT_ASSESSMENT_NO_HUMAN_DECISION',
                                       'run_id':deployment.CANARY_RECOVERY_RUN,'input_ref':self.ref}}
        self.job={'run_id':deployment.CANARY_RECOVERY_RUN,'object_id':self.source['object_id'],
                  'owner_sub':'DEPLOYMENT_CANARY','input_ref':self.ref,'input_hash':self.source['input_hash'],
                  'data_revision':self.source['data_revision'],'status':'QUEUED','attempt':0,'result_ref':None}
        self.db.rows[('jobs',deployment.CANARY_RECOVERY_RUN,'STATE')]=Row(copy.deepcopy(self.job),1)
        self.db.rows[('jobs','OUTBOX',deployment.CANARY_RECOVERY_RUN)]=Row({'run_id':deployment.CANARY_RECOVERY_RUN,'input_hash':self.source['input_hash']},1)
        self.version=pin['version_id'];self.read_calls=[]

    def get_object(self,**kwargs):
        pin=deployment.CANARY_RECOVERY_REPORT
        self.assertEqual(kwargs,{'Bucket':pin['bucket'],'Key':pin['key'],'VersionId':pin['version_id']})
        self.read_calls.append(kwargs)
        return {'VersionId':self.version,'Body':io.BytesIO(encode(self.prior))}

    def recover(self):
        with patch.object(deployment,'CANARY_RECOVERY_INPUT',self.ref):
            return deployment.recover_business_canary(self,self.db,self.blobs,self.resources)

    def test_queued_job_reuses_exact_input_with_no_writes(self):
        before=copy.deepcopy(self.db.rows);blobs=copy.deepcopy(self.blobs.data)
        rid,source,ref,job,pin=self.recover()
        self.assertEqual(rid,deployment.CANARY_RECOVERY_RUN);self.assertEqual(source,self.source)
        self.assertEqual(ref,self.ref);self.assertEqual(job,self.job)
        self.assertEqual(self.db.rows,before);self.assertEqual(self.blobs.data,blobs)
        self.assertEqual(pin['build_id'],'authority-delta-deploy:02244729-c866-4424-885b-6fe8d0209dd6')

    def test_running_and_completed_jobs_are_reused_without_reset(self):
        key=('jobs',deployment.CANARY_RECOVERY_RUN,'STATE')
        self.db.rows[key]=Row(dict(self.job,status='RUNNING',attempt=1),2)
        self.assertEqual(self.recover()[3]['status'],'RUNNING')
        result_ref=self.blobs.put('business/results/retained.json',encode(observed(self.source)))
        self.db.rows[key]=Row(dict(self.job,status='REVIEW_REQUIRED',attempt=1,result_ref=result_ref),3)
        before=copy.deepcopy(self.db.rows)
        self.assertEqual(self.recover()[3]['result_ref'],result_ref);self.assertEqual(self.db.rows,before)

    def test_owner_input_and_outbox_mismatches_fail_closed(self):
        key=('jobs',deployment.CANARY_RECOVERY_RUN,'STATE')
        for field,value in [('owner_sub','real-human'),('input_hash','0'*64),('object_id','another-object'),('data_revision',99),('input_ref',dict(self.ref,version_id='other'))]:
            with self.subTest(field=field):
                self.db.rows[key]=Row(dict(self.job,**{field:value}),1)
                with self.assertRaises(ValueError):self.recover()
        self.db.rows[key]=Row(copy.deepcopy(self.job),1)
        self.db.rows[('jobs','OUTBOX',deployment.CANARY_RECOVERY_RUN)]=Row({'run_id':deployment.CANARY_RECOVERY_RUN,'input_hash':'0'*64},1)
        with self.assertRaises(ValueError):self.recover()

    def test_report_version_source_resources_and_input_bytes_must_match(self):
        for field,value in [('build_id','other-build'),('source_sha256','0'*64),('result','PASS'),('state_unchanged',False),('approval_recorded',True)]:
            with self.subTest(field=field):
                old=self.prior[field];self.prior[field]=value
                with self.assertRaises(ValueError):self.recover()
                self.prior[field]=old
        self.version='another-version'
        with self.assertRaises(ValueError):self.recover()
        self.version=deployment.CANARY_RECOVERY_REPORT['version_id']
        self.resources['JobsTable']='replaced-table'
        with self.assertRaises(ValueError):self.recover()
        self.resources['JobsTable']='retained-jobs'
        self.blobs.data[(self.ref['key'],self.ref['version_id'])]=b'{}'
        with self.assertRaises(ValueError):self.recover()

    def test_terminal_jobs_are_not_retried(self):
        for status in ['FAILED','NEEDS_INPUT','CANCELLED']:
            with self.subTest(status=status):
                self.db.rows[('jobs',deployment.CANARY_RECOVERY_RUN,'STATE')]=Row(dict(self.job,status=status,attempt=1),3)
                before=copy.deepcopy(self.db.rows)
                with self.assertRaisesRegex(ValueError,'no automatic model retry'):self.recover()
                self.assertEqual(self.db.rows,before)

    def test_completed_result_cannot_claim_another_input(self):
        result=observed(self.source);result['input_hash']='0'*64
        ref=self.blobs.put('business/results/retained.json',encode(result))
        self.db.rows[('jobs',deployment.CANARY_RECOVERY_RUN,'STATE')]=Row(dict(self.job,status='REVIEW_REQUIRED',attempt=1,result_ref=ref),3)
        with self.assertRaisesRegex(ValueError,'pinned input'):self.recover()

    def test_runtime_is_reused_only_with_exact_version_and_verified_bytes(self):
        raw=b'LOCAL_ARCHIVE_BYTES'
        pin=dict(deployment.CANARY_RECOVERY_RUNTIME,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
        prior={'artifacts':{'runtime':dict(pin)}}
        class Client:
            payload=raw
            version=pin['version_id']
            def get_object(client,**kwargs):
                self.assertEqual(kwargs,{'Bucket':pin['bucket'],'Key':pin['key'],'VersionId':pin['version_id']})
                return {'VersionId':client.version,'Body':io.BytesIO(client.payload)}
        client=Client()
        with patch.object(deployment,'CANARY_RECOVERY_RUNTIME',pin):
            result=deployment.recovery_runtime_artifact(client,prior)
            self.assertEqual(result['key'],pin['key']);self.assertTrue(result['reused_from_pinned_deployment'])
            for key,value in [('version_id','other-version'),('key','other-key'),('bucket','other-bucket')]:
                wrong=copy.deepcopy(prior);wrong['artifacts']['runtime'][key]=value
                with self.assertRaises(ValueError):deployment.recovery_runtime_artifact(client,wrong)
            client.payload=b'corrupt'
            with self.assertRaises(ValueError):deployment.recovery_runtime_artifact(client,prior)
            client.payload=raw;client.version='wrong-response-version'
            with self.assertRaises(ValueError):deployment.recovery_runtime_artifact(client,prior)


if __name__=='__main__':unittest.main()
