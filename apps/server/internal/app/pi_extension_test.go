package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPiExtensionPersistentTransport(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the generated Pi extension")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake.mjs")
	wrapper := filepath.Join(dir, "wrapper")
	files := map[string][]byte{
		fake: []byte(`import readline from 'node:readline';
const reply=(id,result)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n');
for await(const line of readline.createInterface({input:process.stdin})) {
 const r=JSON.parse(line);
 if(r.method==='initialize') reply(r.id,{});
 if(r.method==='tools/list') reply(r.id,{tools:[{name:'hasp_test',inputSchema:{properties:{project_root:{type:'string'}}}}]});
 if(r.method==='tools/call') {
  const a=r.params.arguments;
  if(a.drop) process.exit(0);
  if(a.hang) continue;
  setTimeout(()=>reply(r.id,a.partial?{isError:true,content:[{type:'text',text:'partial-match-retained'}]}:{pid:process.pid,value:a.value,root:a.project_root,guard:process.env.HASP_AGENT_SAFE_MODE}),a.delay||0);
 }
}`),
		wrapper:                             []byte("#!/bin/sh\nexec " + shellQuoteArg(node) + " " + shellQuoteArg(fake) + "\n"),
		filepath.Join(dir, "extension.mjs"): setupPiExtensionContent(wrapper, "pi"),
		filepath.Join(dir, "test.mjs"): []byte(`import assert from 'node:assert/strict';
import extension from './extension.mjs';
const tools=new Map(),events=new Map();
await extension({registerTool:t=>tools.set(t.name,t),on:(n,f)=>events.set(n,f)});
const call=(args,signal)=>tools.get('hasp_test').execute('id',args,signal,()=>{},{cwd:'/tmp'});
try {
 assert.equal(process.env.HASP_AGENT_SAFE_MODE,'1');
 const [a,b]=await Promise.all([call({value:'first',delay:20}),call({value:'second'})]);
 assert.equal(a.details.pid,b.details.pid); assert.equal(a.details.value,'first'); assert.equal(b.details.value,'second');
 assert.equal(a.details.root,'/tmp'); assert.equal(a.details.guard,'1');
 await assert.rejects(call({partial:true}),/partial-match-retained/);
 await assert.rejects(call({drop:true}),/outcomes are unknown/);
 const disconnected=await tools.get('hasp_status').execute(); assert.equal(disconnected.details.connection,'disconnected');
 const c=await call({value:'reconnected'}); assert.notEqual(c.details.pid,a.details.pid);
 const controller=new AbortController(); const hanging=call({hang:true},controller.signal);
 setTimeout(()=>controller.abort(),10); await assert.rejects(hanging,/outcome is unknown/);
 const cancelled=new AbortController(); cancelled.abort(); await assert.rejects(call({},cancelled.signal),/before sending/);
} finally { await events.get('session_shutdown')(); }
`),
		filepath.Join(dir, "idle.mjs"): []byte(`import extension from './extension.mjs';
await extension({registerTool:()=>{},on:()=>{}});
// An SDK embedding can dispose without a shutdown event. Idle IPC must not
// keep its host process alive.
`),
	}
	for path, data := range files {
		mode := os.FileMode(0o600)
		if path == wrapper {
			mode = 0o700
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, node, filepath.Join(dir, "test.mjs")).CombinedOutput(); err != nil {
		t.Fatalf("generated Pi extension: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(ctx, node, filepath.Join(dir, "idle.mjs")).CombinedOutput(); err != nil {
		t.Fatalf("idle Pi extension kept its host alive: %v\n%s", err, out)
	}
}
