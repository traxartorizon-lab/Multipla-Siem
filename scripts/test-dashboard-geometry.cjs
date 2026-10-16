'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('web/dashboard.js','utf8').split('const resourceTemplate=')[0];
assert(!/[\u00c3\u00c2\ufffd]/.test(source),'dashboard text encoding is corrupted');
const sandbox={};vm.createContext(sandbox);vm.runInContext(source+'\nglobalThis.geometry=dashboardGeometry;globalThis.defaults=dashboardDefaultGeometry;',sandbox);
const g=sandbox.geometry,order=['collection','alerts','devices','response','resources','activity','recent-alerts','posture'];
let cases=0;
function valid(layout,width){for(const [id,card] of Object.entries(layout)){assert(g.valid(id,card,layout,width),id+' overlaps or overflows');const min=g.minimum(id,width);assert(card.pixel_width>=min.width&&card.height>=min.height);cases++}}
for(const width of [320,601,720,859,860,999,1000,1082,1083,1280,1920]){
 const clean=g.fit(sandbox.defaults(width),order,width);valid(clean,width);
 assert.equal(clean.activity.y,0,'main graph is not at the top');if(width>=1000)assert.equal(clean.collection.y,clean.response.y,'metric row is asymmetric');
 const before=JSON.stringify(clean);valid(g.fit(clean,order,width),width);assert.equal(JSON.stringify(clean),before,'fit mutated preferences');assert.equal(JSON.stringify(g.fit(clean,order,width)),before,'valid layout moved');
 const legacy=Object.fromEntries(order.map((id,i)=>[id,{x:i%2?4000:0,y:0,pixel_width:8000,height:120}]));valid(g.fit(legacy,order,width),width);
}
const manual={a:{x:0,y:0,pixel_width:220,height:190},b:{x:240,y:0,pixel_width:220,height:190}};
valid(g.fit(Object.fromEntries(order.map(id=>[id,{x:0,y:48000,pixel_width:8000,height:2400}])),order,601),601);
assert(!g.valid('a',{...manual.a,x:30},manual,900),'drag collision allowed');assert(!g.valid('a',{...manual.a,pixel_width:250},manual,900),'resize collision allowed');assert(g.valid('a',{...manual.a,y:210},manual,900));cases+=3;
let seed=817;for(let n=0;n<200;n++){const random=()=>((seed=(seed*1664525+1013904223)>>>0)/2**32);const width=601+Math.floor(random()*1200);const settings=Object.fromEntries(order.map(id=>[id,{x:Math.floor(random()*4000),y:Math.floor(random()*1000),pixel_width:120+Math.floor(random()*6000),height:120+Math.floor(random()*600)}]));valid(g.fit(settings,order,width),width)}
console.log('PASS '+cases+' dashboard geometry checks: collision, bounded viewport, useful minima, legacy repair and stable fit.');
