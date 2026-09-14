// Real DOM events -> BusinessApi -> Python handler/service. All external systems are local doubles.
import {JSDOM} from 'jsdom';
import {build} from 'esbuild';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const dom=new JSDOM('<div id="root"></div>',{url:'https://dtest.cloudfront.net/'});
for(const key of ['window','document','HTMLElement','HTMLInputElement','HTMLTextAreaElement','HTMLSelectElement','Event','MouseEvent','navigator','sessionStorage','location'])Object.defineProperty(globalThis,key,{value:dom.window[key],configurable:true});
globalThis.IS_REACT_ACT_ENVIRONMENT=true;
let scrolls=0;dom.window.scrollTo=()=>{scrolls++;};
const {createElement:h,act,useState}=await import('react');
const {createRoot}=await import('react-dom/client');
await mkdir('.test',{recursive:true});
await build({entryPoints:['src/BusinessApp.tsx'],bundle:true,packages:'external',loader:{'.css':'empty'},outfile:'.test/flow-view.mjs',format:'esm',platform:'node',jsx:'automatic'});
await build({entryPoints:['src/business-api.ts'],bundle:true,outfile:'.test/flow-api.mjs',format:'esm',platform:'node'});
const {CreateObject,ObjectWorkspace}=await import('./.test/flow-view.mjs');
const {BusinessApi}=await import('./.test/flow-api.mjs');
const child=spawn(process.env.AD_TEST_PYTHON||'python3',['../tests/support/business_ui_rpc.py'],{env:{...process.env,PYTHONPATH:'../src:../scripts:../tests:..',AWS_EC2_METADATA_DISABLED:'true'},stdio:['pipe','pipe','inherit']});
let seq=0;const pending=new Map(),posts=[],checks=[],errors=[];
createInterface({input:child.stdout}).on('line',line=>{const v=JSON.parse(line),p=pending.get(v.id);pending.delete(v.id);if(v.error)p.reject(new Error(v.error+'\n'+v.trace));else p.resolve(v.result);});
child.on('exit',code=>{for(const p of pending.values())p.reject(new Error('Bridge exited '+code));});
function rpc(value){return new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});child.stdin.write(JSON.stringify({id,...value})+'\n');});}
const token='LOCAL.'+btoa(JSON.stringify({scope:'authority-delta/read authority-delta/write authority-delta/approve authority-delta/publish'}))+'.TEST';
sessionStorage.setItem('authority-delta-session',JSON.stringify({token,expires:Date.now()+600000}));
globalThis.fetch=async(url,init={})=>{const path=new URL(url).pathname,method=init.method||'GET',body=init.body?JSON.parse(init.body):undefined;if(method==='POST')posts.push({path,body});const r=await rpc({kind:'api',path,method,body});return new Response(r.body,{status:r.statusCode,headers:r.headers});};
const api=new BusinessApi({client_id:'local',auth_origin:'https://authority-delta-test.auth.ap-northeast-1.amazoncognito.com',api_origin:'https://apitest.execute-api.ap-northeast-1.amazonaws.com',redirect_uri:location.origin+'/'});
let control={},currentDetail;
function Harness(){const [detail,setDetail]=useState(null),[tab,setTab]=useState('evidence'),[busy,setBusy]=useState(false);currentDetail=detail;
 const refresh=async(oid=detail?.object.object_id)=>{if(oid)setDetail(await api.get('/business/objects/'+oid));};
 async function perform(f){setBusy(true);try{return await f();}catch(e){errors.push(e);}finally{setBusy(false);}}
 control={newObject:()=>{setDetail(null);setTab('evidence');},refresh};
 if(!detail)return h(CreateObject,{lang:'en',busy,onCreate:v=>perform(async()=>{const r=await api.post('/business/objects',v);await refresh(r.object_id);})});
 return h(ObjectWorkspace,{key:detail.object.object_id,detail,api,lang:'en',tab,setTab,busy,perform,refresh,onError:e=>errors.push(e)});
}
const root=createRoot(document.getElementById('root'));
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function settle(check=()=>pending.size===0){for(let i=0;i<220;i++){await act(async()=>{await pause(20);});if(errors.length)throw errors[0];if(check()&&pending.size===0)return;}throw new Error('UI condition not reached: '+document.body.textContent.slice(-1000)+' '+JSON.stringify(currentDetail?.applications));}
function field(label){const l=[...document.querySelectorAll('label.business-field')].find(x=>x.querySelector('span')?.textContent===label);assert.ok(l,'Missing field '+label);return l.querySelector('input,textarea,select');}
async function fill(label,value){const e=field(label),proto=e instanceof HTMLSelectElement?HTMLSelectElement.prototype:e instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;await act(async()=>{Object.getOwnPropertyDescriptor(proto,'value').set.call(e,value);e.dispatchEvent(new Event(e instanceof HTMLSelectElement?'change':'input',{bubbles:true}));});}
async function click(text){const b=[...document.querySelectorAll('button')].find(v=>v.textContent===text);assert.ok(b,'Missing button '+text+' '+document.body.textContent.slice(-1000));assert.ok(!b.disabled,'Disabled button '+text);await act(async()=>b.click());await settle();}
async function create(name,purpose,question){await fill('Business / initiative name',name);await fill('Responsible person','Local test reviewer');await fill('Business purpose',purpose);await fill('Question to assess',question);await fill('Goal / measurement (optional)','No observed metrics yet.');await click('Create and add evidence');return currentDetail.object.object_id;}
async function upload(name,text){const e=field('Evidence file'),f=new dom.window.File([text],name,{type:'text/plain'});f.arrayBuffer=async()=>new TextEncoder().encode(text).buffer;Object.defineProperty(e,'files',{value:[f],configurable:true});await act(async()=>e.dispatchEvent(new Event('change',{bubbles:true})));await fill('Source (optional)','Synthetic local flow test');// jsdom cannot populate its internal FileList through a native chooser.
 await act(async()=>e.closest('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await settle(()=>currentDetail.evidence.some(v=>v.filename===name));}
async function assess(){await click('Start assessment');await settle(()=>document.body.textContent.includes('Review the proposed decision'));}
async function approvePublish(){await click('Review the proposed decision');await fill('Review / edit note','Synthetic reviewer checks the source-backed draft.');await click('Save decision draft');const before=currentDetail.object.published_current;await fill('Reason for your decision','Synthetic reviewer approves this exact saved draft.');await click('Record approval');assert.deepEqual(currentDetail.object.published_current,before);assert.equal(currentDetail.object.applied_binding,null);await click('Publish this decision');assert.ok(currentDetail.object.published_current);assert.ok(document.querySelector('[aria-label="Publication complete"]'));assert.ok(![...document.querySelectorAll('button')].some(b=>b.textContent==='This decision is published'));const scrollBefore=scrolls;await click('View official decision');assert.equal(scrolls,scrollBefore+1);assert.ok(document.body.textContent.includes('THE QUESTION'));await click('Review & publish');await click('View history and records');assert.ok(document.body.textContent.includes('Download acceptance evidence'));await click('Review & publish');}
try{
 await act(async()=>root.render(h(Harness)));
 const nonpayment=await create('Customer data sharing — local acceptance','Review customer data sharing with an external provider','Under what conditions may customer data be shared?');
 await upload('sharing.txt','Customer data sharing requires owner approval. Approval and processor terms have not been supplied.');await assess();await approvePublish();
 assert.equal(currentDetail.available_adapters.length,0);assert.equal(currentDetail.object.applied_binding,null);assert.ok(document.body.textContent.includes('No AWS execution adapter is connected.'));assert.ok(!document.body.textContent.includes('Approve AWS delegation separately'));checks.push('nonpayment_create_evidence_assess_review_publish_without_implicit_adapter');
 await act(async()=>control.newObject());
 const payment=await create('VendorPayment — local acceptance','Evaluate a bounded synthetic vendor payment workflow','Which vendor payment requests fit the registered boundary?');
 await upload('vendor.txt','This synthetic vendor workflow requires an owner decision. No real payment is made.');await assess();await approvePublish();
 const selector=[...document.querySelectorAll('summary')].find(v=>v.textContent==='Select a matching AWS connection (optional)');assert.ok(selector);await act(async()=>selector.click());assert.ok(selector.parentElement.open);
 const adapter=currentDetail.registered_adapters[0];await fill('Execution connection for this business',adapter.adapter_id+'|'+adapter.connection_id);await fill('Why this connection applies to this business','This is the explicit synthetic vendor payment execution test.');await click('Save connection for this business');assert.equal(currentDetail.object.delegation_approval,null);assert.equal(currentDetail.object.application_status,'NOT_APPLIED');checks.push('explicit_connection_save_does_not_grant_authority');
 await fill('Registered delegation profile','NARROW');await fill('Reason for AWS delegation','Synthetic reviewer authorizes the bounded recovery test.');await click('Approve AWS delegation separately');assert.equal(currentDetail.object.applied_binding,null);await rpc({kind:'publisher_mode',value:'RECOVERED_CLOSED'});await click('Start closed application and verification');await settle(()=>currentDetail.object.latest_application?.status==='RECOVERED_CLOSED');checks.push('separate_delegation_application_and_closed_recovery');
 await click('Actions');await fill('Owner','Local test reviewer');await fill('Due date','2026-09-30');await fill('Update reason','Assign the action for this synthetic test.');await click('Save action status');
 await click('Evidence');await upload('resolution.txt','The test owner has now documented the permitted synthetic scope. This evidence does not authorize real payments.');
 await click('Actions');await fill('Next status','COMPLETED');await fill('Update reason','The new evidence resolves this local test action.');const box=document.querySelector('.business-action-evidence-choices input');assert.ok(box);await act(async()=>box.click());await click('Complete with evidence');
 await click('Evidence');await assess();await approvePublish();checks.push('action_assignment_completion_and_new_evidence_reassessment_publication');
 await fill('Reason for AWS delegation','Synthetic reviewer authorizes the verified application test.');await click('Approve AWS delegation separately');await rpc({kind:'publisher_mode',value:'VERIFIED'});await click('Start closed application and verification');await settle(()=>currentDetail.object.application_status==='VERIFIED');
 await click('Outcomes & exchange');const application=currentDetail.applications.find(a=>a.status==='VERIFIED');assert.ok(application);await fill('Record this outcome against',application.application_id);await fill('Authority result','ALLOW');await fill('Business result','Expected finite outcomes verified by the local scripted publisher.');await click('Record outcome');
 const sent=posts.filter(p=>p.path.endsWith('/outcomes')).at(-1);assert.equal(sent.body.target.kind,'AWS_APPLICATION');assert.equal(sent.body.target.digest,application.enforcement_digest);assert.equal(currentDetail.outcome_records[0].target.id,application.application_id);checks.push('outcome_click_posts_and_saves_the_verified_application_binding');
 const composed=await rpc({kind:'check',payment,nonpayment});assert.equal(composed.result,'PASS');assert.equal(composed.product_ready,false);checks.push('saved_exports_pass_positive_composition_without_product_promotion');
 await click('Review & publish');await fill('Decision summary','Unsaved revised judgment.');assert.equal(document.querySelector('[aria-label="Publication complete"]'),null);checks.push('unsaved_revision_is_not_presented_as_published');
 const result={scope:'LOCAL_REACT_DOM_TO_REAL_API_MEMORY_STORAGE_SCRIPTED_MODEL_AWS_IDENTITY',result:'PASS',checks,live_aws:'NOT_RUN',live_model:'NOT_RUN',browser_visual_qa:'NOT_RUN',authenticated_human_acceptance:'NOT_RUN'};
 await writeFile('../evidence/local/business-dom-flow.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}finally{await act(async()=>root.unmount());child.stdin.end();dom.window.close();}
