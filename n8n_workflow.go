package main

// n8nWorkflow uses only built-in nodes. Credentials stay in n8n's credential
// store; they are never included in an exported workflow or a Code node.
func n8nWorkflow() map[string]any {
	node := func(id, name, kind string, version float64, x, y int, parameters map[string]any) map[string]any {
		return map[string]any{"id": id, "name": name, "type": "n8n-nodes-base." + kind, "typeVersion": version, "position": []int{x, y}, "parameters": parameters}
	}
	webhook := node("receiver", "Receber alerta Multipla", "webhook", 2, 0, 0, map[string]any{"httpMethod": "POST", "path": "multipla-siem-" + token()[:16], "authentication": "headerAuth", "responseMode": "responseNode", "options": map[string]any{}})
	webhook["notes"] = "Crie uma credencial Header Auth: Name = X-Multipla-Token; Value = token gerado no SIEM. Selecione-a neste nó. Publique o fluxo e copie a Production URL. Nunca selecione Authentication None."
	webhook["notesInFlow"] = true
	validate := node("validate", "Validar e remover cabeçalhos", "code", 2, 260, 0, map[string]any{"jsCode": n8nValidationCode})
	branch := node("test-branch", "É teste de conexão?", "if", 2, 500, 0, map[string]any{"conditions": map[string]any{"options": map[string]any{"caseSensitive": true, "leftValue": "", "typeValidation": "strict", "version": 2}, "conditions": []any{map[string]any{"id": "kind-test", "leftValue": "={{ $json.kind }}", "rightValue": "test", "operator": map[string]any{"type": "string", "operation": "equals"}}}, "combinator": "and"}, "options": map[string]any{}})
	response := map[string]any{"respondWith": "json", "responseBody": "={{ { ok: true, schema: 1, id: $json.id, kind: $json.kind } }}", "options": map[string]any{"responseCode": 200}}
	test := node("test-ok", "Confirmar teste sem automações", "respondToWebhook", 1.4, 760, -130, response)
	accepted := node("alert-ok", "Confirmar recebimento do alerta", "respondToWebhook", 1.4, 760, 130, response)
	actions := node("actions", "Conectar sua automação aqui", "noOp", 1, 1020, 130, map[string]any{})
	actions["notes"] = "Conecte notificações ou chamados aqui. A confirmação significa recebimento validado, não conclusão da automação. Entregas podem repetir: antes de ações irreversíveis, deduplique por id com índice UNIQUE em armazenamento persistente. Não execute title/device como comandos. Eventos de teste nunca chegam a este ramo."
	actions["notesInFlow"] = true
	link := func(name string) map[string]any { return map[string]any{"node": name, "type": "main", "index": 0} }
	return map[string]any{"name": "Multipla SIEM · receber alertas com autenticação", "active": false, "nodes": []any{webhook, validate, branch, test, accepted, actions}, "connections": map[string]any{
		"Receber alerta Multipla":         map[string]any{"main": [][]any{{link("Validar e remover cabeçalhos")}}},
		"Validar e remover cabeçalhos":    map[string]any{"main": [][]any{{link("É teste de conexão?")}}},
		"É teste de conexão?":             map[string]any{"main": [][]any{{link("Confirmar teste sem automações")}, {link("Confirmar recebimento do alerta")}}},
		"Confirmar recebimento do alerta": map[string]any{"main": [][]any{{link("Conectar sua automação aqui")}}},
	}, "settings": map[string]any{"executionOrder": "v1", "saveDataErrorExecution": "none", "saveDataSuccessExecution": "none", "saveManualExecutions": false, "saveExecutionProgress": false, "executionTimeout": 30}, "pinData": map[string]any{}}
}

const n8nValidationCode = `const input = $input.first().json;
const b = input.body, h = input.headers || {};
if (!b || typeof b !== 'object' || Array.isArray(b)) throw new Error('Payload inválido');
const keys = ['schema','product','version','kind','id','time','device','protocol','source_ip','level','title'];
if (Object.keys(b).some(k => !keys.includes(k)) || keys.some(k => !(k in b))) throw new Error('Campos inválidos');
const timestamp = Number(h['x-multipla-timestamp']);
if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now()/1000-timestamp)>300) throw new Error('Envio expirado');
if (b.schema!==1 || b.product!=='Multipla Siem' || !['alert','test'].includes(b.kind)) throw new Error('Esquema inválido');
if (typeof b.id!=='string' || !/^[A-Za-z0-9_-]{16,128}$/.test(b.id) || h['x-multipla-event-id']!==b.id) throw new Error('ID inválido');
if (!Number.isInteger(b.level) || b.level<1 || b.level>15 || typeof b.time!=='string' || b.time.length>64 || !Number.isFinite(Date.parse(b.time))) throw new Error('Evento inválido');
for (const [key,max] of [['version',64],['device',256],['protocol',64],['source_ip',64],['title',1024]]) {
 if (typeof b[key]!=='string' || b[key].length>max || /[\u0000\r\n]/.test(b[key])) throw new Error('Texto inválido');
}
// Return only the defined contract: authentication headers never reach action nodes.
return [{json:Object.fromEntries(keys.map(k=>[k,b[k]]))}];`
