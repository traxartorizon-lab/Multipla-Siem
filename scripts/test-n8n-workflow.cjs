const fs=require('fs'),assert=require('assert');
const go=fs.readFileSync('n8n_workflow.go','utf8');
const code=go.split('const n8nValidationCode = `')[1].split('`')[0];
function validate(body,headers){return new Function('$input',code)({first:()=>({json:{body,headers}})})}
const body={schema:1,product:'Multipla Siem',version:'1.2.19',kind:'alert',id:'test-id-0123456789',time:new Date().toISOString(),device:'pfSense',protocol:'syslog',source_ip:'100.83.245.103',level:12,title:'Critical'};
const headers={'x-multipla-timestamp':String(Math.floor(Date.now()/1000)),'x-multipla-event-id':body.id,'x-multipla-token':'not-a-real-credential'};
assert.deepEqual(validate(body,headers),[{json:body}]);
assert.deepEqual(validate({...body,kind:'test'},headers),[{json:{...body,kind:'test'}}]);
assert(!JSON.stringify(validate(body,headers)).includes('not-a-real-credential'));
for(const bad of [{...body,schema:2},{...body,level:0},{...body,kind:'command'},{...body,id:'bad'},{...body,extra:'bad'},{...body,title:'a\nb'},{...body,time:0}])assert.throws(()=>validate(bad,headers));
assert.throws(()=>validate(body,{...headers,'x-multipla-event-id':'other'}));
assert.throws(()=>validate(body,{...headers,'x-multipla-timestamp':'1'}));
assert.throws(()=>validate(body,{...headers,'x-multipla-timestamp':'NaN'}));
console.log('n8n validation: schema, freshness, identity, bounded fields and credential removal passed');
