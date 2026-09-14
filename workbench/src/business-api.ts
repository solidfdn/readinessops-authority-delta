import type {Config} from './types';
import {accessToken, clearSession, nonce} from './auth';
const PENDING='readinessops-pending-command';
export class ApiError extends Error {constructor(message:string,public code:string,public status:number){super(message);}}
export class BusinessApi {
  constructor(public config:Config){}
  async request(path:string,body?:Record<string,unknown>){
    const token=await accessToken(this.config);
    if(!token)throw new ApiError('Sign in to continue.','SIGN_IN_REQUIRED',401);
    let response:Response;
    try{response=await fetch(this.config.api_origin+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(28_000)});}
    catch{throw new ApiError('The operation could not be confirmed. Retry to recover the result of the same operation.','UNCONFIRMED',503);}
    const value=await response.json();
    if(!response.ok){if(response.status===401)clearSession();throw new ApiError(value.error||'Operation failed',value.code||'FAILED',response.status);}
    return value;
  }
  get(path:string){return this.request(path);}
  async post(path:string,body:Record<string,unknown>){
    const existing=sessionStorage.getItem(PENDING);let operation;
    const input=JSON.stringify({path,body});
    if(existing){operation=JSON.parse(existing);if(operation.input!==input)throw new ApiError('Recover the previous operation before making another change.','PENDING_COMMAND',409);}
    else{operation={path,body:{...body,request_id:nonce()},input};sessionStorage.setItem(PENDING,JSON.stringify(operation));}
    return this.sendSaved(operation);
  }
  async invoke(path:string,requestId:string){
    const existing=sessionStorage.getItem(PENDING);let operation;
    const body={operation_id:nonce(),request_id:requestId};
    if(existing){operation=JSON.parse(existing);if(operation.path!==path||operation.body?.request_id!==requestId||!operation.body?.operation_id)throw new ApiError('Recover the previous operation before making another change.','PENDING_COMMAND',409);}
    else{operation={path,body,input:JSON.stringify({path,body})};sessionStorage.setItem(PENDING,JSON.stringify(operation));}
    return this.sendSaved(operation);
  }
  async recover(){const saved=sessionStorage.getItem(PENDING);return saved?this.sendSaved(JSON.parse(saved)):null;}
  hasPending(){return sessionStorage.getItem(PENDING)!==null;}
  async sendSaved(operation:{path:string;body:Record<string,unknown>}){
    try{const result=await this.request(operation.path,operation.body);sessionStorage.removeItem(PENDING);return result;}
    catch(e){if(e instanceof ApiError && e.status>=400&&e.status<500&&![401,403,429].includes(e.status))sessionStorage.removeItem(PENDING);throw e;}
  }
}
export function needsBusinessSignIn(token:string){
  try{const p=JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));return !['read','write','approve','publish'].every(s=>String(p.scope||'').split(' ').includes('authority-delta/'+s));}
  catch{return true;}
}
