import {build} from 'esbuild';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {renderToStaticMarkup} from 'react-dom/server';
import {createElement} from 'react';
await mkdir('.test',{recursive:true});
await build({entryPoints:['src/App.tsx'],bundle:true,packages:'external',loader:{'.css':'empty'},outfile:'.test/view.mjs',format:'esm',platform:'node',jsx:'automatic'});
await build({entryPoints:['src/BusinessApp.tsx'],bundle:true,packages:'external',loader:{'.css':'empty'},outfile:'.test/business-view.mjs',format:'esm',platform:'node',jsx:'automatic'});
await build({entryPoints:['src/auth.ts'],bundle:true,outfile:'.test/auth.mjs',format:'esm',platform:'node'});
const {ReviewView,WorkspaceView}=await import('./.test/view.mjs');
const {AuthorityPanel,ActionTracker,OutcomeExchange,validIsoDate}=await import('./.test/business-view.mjs');
assert.equal(validIsoDate('2026-09-30'),true);assert.equal(validIsoDate('2026-02-30'),false);assert.equal(validIsoDate('09/30/2026'),false);
const businessBundle=await readFile('.test/business-view.mjs','utf8');
for(const text of ['Choose file','No file selected','YYYY-MM-DD'])assert.ok(businessBundle.includes(text),text);
const data=JSON.parse(await readFile('.test/review.json','utf8'));
let html=renderToStaticMarkup(createElement(ReviewView,{data}));
for(const text of ['One judgment needs you.','P-002','Preview only','No approval is recorded','All 6 observed scenarios','Would allow','Would deny','Auxiliary control']) assert.ok(html.includes(text),text);
for(const [initialSection,expected] of Object.entries({overview:['Business objects &amp; agents','Human decisions recorded','Sample workspace'],evidence:['Know what supports the review.','Source version:','Download evidence'],findings:['Gap','Risk to review','REQUIRED ACTION','P-002'],review:['One judgment needs you.','Preview only'],history:['Recorded analysis','No decision receipt or publication result yet.']})){
  const screen=renderToStaticMarkup(createElement(WorkspaceView,{data,initialSection}));
  for(const text of expected)assert.ok(screen.includes(text),initialSection+': '+text);
  assert.ok(!screen.includes('Approve payment'));
}
// Changing the trusted business presentation must not leave hard-coded monetary UI.
// This is a rendering contract, not a second live AWS adapter or semantic proof.
const sharing=structuredClone(data);sharing.presentation.columns=[{id:'audience',label:'Audience'}];
for(const [id,row] of Object.entries(sharing.presentation.rows))sharing.presentation.rows[id]={audience:id==='P-002'?'External partner':'Internal staff'};
sharing.presentation.boundary_note='External sharing stays subject to human review.';
sharing.presentation.decisions=[{id:'MAINTAIN',title:'Keep sharing boundary',text:'Preserve the approved audience.'},{id:'NARROW',title:'Internal only',text:'Restrict the audience.'},{id:'REJECT',title:'Reject release',text:'Keep the current release.'}];
sharing.presentation.preview_summaries={MAINTAIN:'Approved audiences only',NARROW:'Internal audiences only',REJECT:'No candidate authority'};
for(const comparison of Object.values(sharing.comparisons)){
  comparison.definitions={};comparison.patch.analysis.summary='Review audience changes.';
  comparison.patch.analysis.maintain_proposal='Keep external sharing subject to review.';
  comparison.patch.analysis.counterexamples=[];
  for(const change of comparison.patch.analysis.changes){change.reason='External partners now count as internal.';change.definition_fields=[];change.evidence_refs=['definitions/audiences'];}
}
const sharedHtml=renderToStaticMarkup(createElement(ReviewView,{data:sharing}));
assert.ok(sharedHtml.includes('Audience')&&sharedHtml.includes('External partner'));
assert.ok(!/payment|bank|USD|500|300/i.test(sharedHtml));
const attack=structuredClone(data);attack.comparisons.semantic.patch.analysis.changes[0].reason='<script>alert("unsafe")</script>';
html=renderToStaticMarkup(createElement(ReviewView,{data:attack}));
assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
const storage=new Map();globalThis.sessionStorage={getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)};
let assigned='';globalThis.location={origin:'https://dtest.cloudfront.net',search:'',assign:u=>assigned=u};
globalThis.history={replaceState:()=>{location.search=''}};
const auth=await import('./.test/auth.mjs');
const config=auth.checkedConfig({client_id:'client123',auth_origin:'https://authority-delta-test.auth.ap-northeast-1.amazoncognito.com',api_origin:'https://api123.execute-api.ap-northeast-1.amazonaws.com',redirect_uri:location.origin+'/'});
assert.throws(()=>auth.checkedConfig({...config,redirect_uri:'https://foreign.example/'}));
await auth.startSignIn(config);
const url=new URL(assigned), saved=JSON.parse(storage.get('authority-delta-pkce'));
assert.equal(url.searchParams.get('code_challenge_method'),'S256');
assert.equal(url.searchParams.get('code_challenge'),createHash('sha256').update(saved.verifier).digest('base64url'));
let fetched=0;globalThis.fetch=async()=>{fetched++;return {ok:true,json:async()=>({token_type:'Bearer',access_token:'local-test-token',expires_in:900})}};
location.search='?code=test&state=wrong';await assert.rejects(auth.accessToken(config),/could not be verified/);assert.equal(fetched,0);
await auth.startSignIn(config);const valid=JSON.parse(storage.get('authority-delta-pkce'));location.search='?code=test&state='+valid.state;
assert.equal(await auth.accessToken(config),'local-test-token');assert.equal(fetched,1);assert.equal(location.search,'');assert.equal(storage.has('authority-delta-pkce'),false);
auth.signOut(config);assert.equal(storage.has('authority-delta-session'),false);assert.ok(assigned.startsWith(config.auth_origin+'/logout?'));
storage.set('authority-delta-session',JSON.stringify({token:'expired',expires:0}));assert.equal(await auth.accessToken(config),null);
const authorityBase={object:{object_id:'o-'+'1'.repeat(32),record_revision:7,published_current:{publication_id:'pub-'+'2'.repeat(32),digest:'3'.repeat(64)},application_status:'NOT_APPLIED',delegation_approval:null,latest_application:null,applied_binding:null},available_adapters:[]};
const authorityProps={detail:authorityBase,api:{post:async()=>({})},lang:'en',busy:false,perform:async f=>f(),refresh:async()=>{}};
let authorityHtml=renderToStaticMarkup(createElement(AuthorityPanel,authorityProps));assert.ok(authorityHtml.includes('No AWS execution adapter is connected.'));assert.ok(!authorityHtml.includes('Approve AWS delegation separately'));
const registered=structuredClone(authorityBase);registered.available_adapters=[{adapter_id:'vendor_payment',adapter_version:'1.0.0',connection_id:'conn-local-vendor-payment',connection_mode:'SYNTHETIC_LOCAL',target_account_id:'111122223333',target_region:'ap-northeast-1',release_id:'V2',runtime_version:'2',profiles:[{profile_id:'MAINTAIN',allowed_request_count:2,boundary:{parameters:{max_amount_minor:50000}}}]}];
authorityHtml=renderToStaticMarkup(createElement(AuthorityPanel,{...authorityProps,detail:registered}));for(const text of ['Separately delegate and apply a registered boundary.','conn-local-vendor-payment','SYNTHETIC_LOCAL','Approve AWS delegation separately'])assert.ok(authorityHtml.includes(text),text);assert.ok(!authorityHtml.includes('runtime_authority_active\":true'));
const applied=structuredClone(registered),applicationId='application-'+'4'.repeat(32),requestId='req-'+'5'.repeat(64);applied.available_adapters[0].profiles[0].allowed_request_ids=[requestId];applied.object.applied_binding={application_id:applicationId,publication_id:applied.object.published_current.publication_id,profile_id:'MAINTAIN',runtime_authority_active:true,delegation_expires_at:'2026-09-20T00:00:00+00:00'};applied.object.authority_control={application_id:applicationId,status:'VERIFIED',entry_status:'OPEN',runtime_authority_active:true};
authorityHtml=renderToStaticMarkup(createElement(AuthorityPanel,{...authorityProps,detail:applied}));for(const text of ['Only the current finite authority can execute.','Run with current authority','Close entry and begin suspension',requestId])assert.ok(authorityHtml.includes(text),text);
const stopping=structuredClone(applied);stopping.object.authority_control={...stopping.object.authority_control,status:'UNKNOWN',entry_status:'CLOSED',runtime_authority_active:false,policy_status:'ACTIVE',deny_status:'NOT_CONFIRMED'};
authorityHtml=renderToStaticMarkup(createElement(AuthorityPanel,{...authorityProps,detail:stopping}));for(const text of ['Entry closed. AWS revocation verification is still running.','This is not reported as suspended.','Live DENY: not confirmed'])assert.ok(authorityHtml.includes(text),text);assert.ok(!authorityHtml.includes('AWS authority suspension is confirmed.'));
const suspended=structuredClone(stopping);suspended.object.authority_control={...suspended.object.authority_control,status:'SUSPENDED_CONFIRMED',policy_status:'REMOVED',deny_status:'CONFIRMED'};
authorityHtml=renderToStaticMarkup(createElement(AuthorityPanel,{...authorityProps,detail:suspended}));for(const text of ['AWS authority suspension is confirmed.','owned Policy is absent','live DENY result'])assert.ok(authorityHtml.includes(text),text);
const actionDetail={object:{object_id:'o-'+'1'.repeat(32),record_revision:9,owner:'Operations'},evidence:[{evidence_id:'e-'+'4'.repeat(32),title:'New resolution evidence',extraction_status:'READY'}],action_records:[{action_id:'action-'+'5'.repeat(32),record_revision:1,title:'Confirm processor terms',description:'Obtain the signed terms before proceeding.',finding_ids:['F-01'],baseline_evidence_ids:['e-'+'6'.repeat(32)],publication_id:'pub-'+'2'.repeat(32),status:'PROPOSED',owner:null,due_on:null,reassessment_run_id:null,resolution_evidence:[]}]};
const actionProps={detail:actionDetail,api:{post:async()=>({})},lang:'en',busy:false,perform:async f=>f(),refresh:async()=>{},goEvidence:()=>{}};
let actionHtml=renderToStaticMarkup(createElement(ActionTracker,actionProps));for(const text of ['Turn proposed actions into accountable work.','Proposed — not started','Owner','Due date','YYYY-MM-DD','new resolution evidence'])assert.ok(actionHtml.includes(text),text);assert.ok(!actionHtml.includes('type="date"'));assert.ok(!actionHtml.includes('Completion is backed by new evidence'));
const completed=structuredClone(actionDetail);completed.action_records[0]={...completed.action_records[0],status:'COMPLETED',owner:'Operations',due_on:'2026-09-30',resolution_evidence:[{evidence_id:'e-'+'4'.repeat(32),title:'New resolution evidence'}]};actionHtml=renderToStaticMarkup(createElement(ActionTracker,{...actionProps,detail:completed}));assert.ok(actionHtml.includes('Completion is backed by new evidence'));assert.ok(actionHtml.includes('New resolution evidence'));
const outcomeDetail={object:{object_id:'o-'+'1'.repeat(32),record_revision:11,published_current:{publication_id:'pub-'+'2'.repeat(32),pack_id:'pack-'+'3'.repeat(32),revision:1,digest:'4'.repeat(64)},application_status:'NOT_APPLIED'},outcome_records:[{outcome_id:'outcome-'+'5'.repeat(32),target:{kind:'DECISION_PUBLICATION',id:'pub-'+'2'.repeat(32)},recorded_at:'2026-09-11T00:00:00+00:00',authority_result:'ALLOW',business_result:'Procedure observed',metrics:[{name:'Review time',measurement_status:'NOT_MEASURED',source:'No baseline',reason:'Not collected'}]}],imported_records:[{import_id:'import-'+'6'.repeat(32),authority_source:'snowflake:reference',pack_id:'pack-external',pack_revision:2,outcome_count:1}]};
const outcomeProps={detail:outcomeDetail,api:{get:async()=>({}),post:async()=>({})},lang:'en',busy:false,perform:async f=>f(),refresh:async()=>{}};const outcomeHtml=renderToStaticMarkup(createElement(OutcomeExchange,outcomeProps));for(const text of ['Record outcomes without inventing measurements.','Export fixed version','Not measured','file import is not Snowflake connectivity','snowflake:reference','Choose file','No file selected','business-file-native'])assert.ok(outcomeHtml.includes(text),text);assert.ok(!outcomeHtml.includes('Not measured · 0'));
const report={scope:'LOCAL_REACT_SSR_AND_PKCE_CONTRACT_NO_BROWSER_OR_AWS',result:'PASS',checks:['five_workspace_sections','linked_evidence_and_findings','no_fabricated_decision_or_publication','business_presentation_without_payment_fields','review_render','untrusted_model_text_escaped','redirect_origin_bound','pkce_s256','wrong_state_no_token_request','valid_code_exchange','one_time_state_removed','sign_out_clears_session','expired_session_rejected','single_language_product_shell','browser_locale_independent_file_and_date_controls','unregistered_adapter_closed','separate_registered_delegation','finite_normal_invocation_action','revocation_unknown_not_reported_suspended','suspension_requires_removed_and_deny','action_lifecycle_requires_owner_due_and_new_evidence','outcome_metric_and_fixed_interchange_contract']};
await writeFile('../evidence/local/workbench-ui-contract.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
