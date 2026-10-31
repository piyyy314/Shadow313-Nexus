const {test} = require('node:test');
const assert = require('node:assert/strict');
const {Readable} = require('node:stream');
const {createForms} = require('../server/forms.cjs');
// Non-secret fixtures, never real provider credentials.
const env = {RESEND_API_KEY:'test-fixture', FORM_FROM_EMAIL:'forms@example.test',
  FORM_TO_EMAIL:'operator@example.test', TURNSTILE_SECRET_KEY:'test-fixture', TURNSTILE_SITE_KEY:'public-fixture'};
const data = {email:'visitor@example.test', token:'test-response', consent:true, website:''};
async function run({config=env, body=data, method='POST', origin='https://shadow313.com',
  type='application/json', path='/api/waitlist', fetcher}={}) {
  const calls = [];
  const client = fetcher || (async (url, options) => {
    calls.push({url, body:JSON.parse(options.body)});
    return {ok:true, json:async () => url.includes('siteverify') ?
      {success:true, action:path.endsWith('contact') ? 'contact':'waitlist', hostname:new URL(origin).hostname} : {id:'test-id'}};
  });
  const req = Readable.from([typeof body === 'string' ? body : JSON.stringify(body)]);
  Object.assign(req, {method, headers:{origin, 'content-type':type}});
  let result;
  const res = {headers:{}, setHeader(k,v){this.headers[k]=v;}, end(value){result=JSON.parse(value);}};
  await createForms({env:config, fetcher:client})(req,res,path);
  return {status:res.statusCode, body:result, calls, headers:res.headers};
}
test('unconfigured forms fail closed and config reveals no secrets', async () => {
  assert.equal((await run({config:{}})).status,503);
  const config = await run({method:'GET',path:'/api/forms/config'});
  assert.deepEqual(config.body,{enabled:true,siteKey:'public-fixture'});
  assert.ok(!JSON.stringify(config.body).includes('test-fixture'));
});
test('valid waitlist request verifies CAPTCHA before emailing only configured operator', async () => {
  const result=await run();
  assert.equal(result.status,202); assert.equal(result.calls.length,2);
  assert.match(result.calls[0].url,/siteverify/);
  assert.deepEqual(result.calls[1].body.to,['operator@example.test']);
  assert.equal(result.calls[1].body.reply_to,data.email);
  assert.match(result.body.message,/Inbox delivery is not yet confirmed/);
});
test('contact content is plain text and supplied recipient cannot redirect delivery', async () => {
  const result=await run({path:'/api/contact',body:{...data,name:'Test',subject:'Question',
    message:'<script>untrusted</script>',to:'attacker@example.test'}});
  assert.equal(result.status,202);
  const mail=result.calls[1].body;
  assert.equal(mail.html,undefined); assert.match(mail.text,/<script>/);
  assert.deepEqual(mail.to,['operator@example.test']);
});
test('reject methods, origins, content types, malformed/large payloads and invalid inputs', async () => {
  for (const options of [{method:'GET'},{origin:'https://attacker.test'}, {type:'text/plain'},
    {body:'{'},{body:'x'.repeat(17000)}, {body:{...data,email:'bad'}},
    {body:{...data,email:'x@example.test\r\nBcc: bad@example.test'}},
    {body:{...data,consent:false}},{body:{...data,website:'spam'}},
    {path:'/api/contact',body:{...data,name:'test'}},
    {path:'/api/contact',body:{...data,name:'test',message:'hi',subject:'x\nBcc:'}}]) {
    const result=await run(options); assert.ok(result.status>=400); assert.equal(result.calls.length,0);
  }
});
test('forged/expired/wrong-action/wrong-host CAPTCHA never sends mail', async () => {
  for (const check of [{success:false},{success:true,action:'wrong',hostname:'shadow313.com'},
    {success:true,action:'waitlist',hostname:'attacker.test'}]) {
    let count=0;
    const result=await run({fetcher:async()=>{count++;return{ok:true,json:async()=>check};}});
    assert.equal(result.status,403); assert.equal(count,1);
  }
});
test('provider rejection or network error cannot produce success', async () => {
  for (const mode of ['network','provider','no-id']) {
    let count=0;
    const result=await run({fetcher:async()=>{
      count++;
      if(mode==='network')throw new Error('fixture');
      if(count===1)return{ok:true,json:async()=>({success:true,action:'waitlist',hostname:'shadow313.com'})};
      return{ok:mode==='no-id',json:async()=>({error:'fixture'})};
    }});
    assert.equal(result.status,502);assert.equal(result.body.accepted,undefined);
  }
});
