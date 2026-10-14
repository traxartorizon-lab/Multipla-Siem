const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync('web/app.js','utf8');
const begin=source.indexOf('async function openCriticalClientFocus(');
const nodes=new Map(),node=id=>{if(!nodes.has(id))nodes.set(id,{value:'',hidden:true,textContent:'',replaceChildren(){}});return nodes.get(id)};
const calls=[];let rendered=0;
const ctx={Date,encodeURIComponent,criticalClientFocus:false,eventClientSelection:'',historyOffset:50,historyQuery:'old',historyEventsData:null,eventFocusRequest:0,criticalClientRange:'',eventFocusBanner:node('banner'),$:node,el:(...args)=>args,clearEventFocus(){ctx.criticalClientFocus=false;ctx.eventFocusRequest++},setEventsLivePaused(p){ctx.paused=p},render(){rendered++},api:async path=>{calls.push(path);return {events:[{id:'critical'}],more:true,partial:false}}};
vm.createContext(ctx);vm.runInContext(source.slice(begin),ctx);
(async()=>{await ctx.openCriticalClientFocus('Alpha');assert(ctx.paused&&ctx.criticalClientFocus);assert.equal(ctx.eventClientSelection,'Alpha');assert.equal(ctx.historyOffset,0);assert(calls[0].includes('critical=1&client=Alpha'));assert(calls[0].includes('&from=')&&calls[0].includes('&to='));assert.equal(rendered,1);const range=ctx.criticalClientRange;ctx.historyOffset=100;await ctx.loadCriticalClientFocus();assert(calls[1].endsWith('&offset=100'));assert.equal(ctx.criticalClientRange,range);console.log('PASS: client critical focus pauses live view, fixed range and pagination')})().catch(e=>{console.error(e);process.exitCode=1});
