// Captures registered tools so tests can call MCP tool handlers directly.
export class McpServer {
	constructor() {
		this.tools = new Map();
	}
	registerTool(name, _definition, handler) {
		this.tools.set(name, handler);
	}
}

export function createMcpHandler(factory) {
	return factory;
}
