import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import { fileURLToPath } from 'url';

/**
 * MCP Security Server for AI Agent Security Monitor.
 *
 * Exposes governance tools (gate_action, evaluate_tool_call, register_agent,
 * log_event, query_compliance) over stdio. Tool handlers are exported as pure
 * functions so they can be unit-tested in-process without spawning a subprocess.
 */

export interface ApiCallFn {
  <T>(endpoint: string, method: string, body?: unknown): Promise<T>;
}

export function createApiCall(baseUrl: string, apiKey: string): ApiCallFn {
  return async function apiCall<T>(endpoint: string, method: string, body?: unknown): Promise<T> {
    const url = `${baseUrl}${endpoint}`;
    const headers: Record<string, string> = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (apiKey) headers['X-API-Key'] = apiKey;

    const response = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API error ${response.status}: ${error}`);
    }
    return response.json() as Promise<T>;
  };
}

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const MCP_TOOLS: McpTool[] = [
  {
    name: 'gate_action',
    description: 'Evaluate a policy decision before agent action execution. Returns allow/deny with a cryptographically-signed certificate.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Unique agent identifier' },
        action: { type: 'string', description: 'Action being performed (e.g., api:call, data:read)' },
        resource: { type: 'string', description: 'Resource being accessed (e.g., /api/users, database:customers)' },
        context: {
          type: 'object',
          description: 'Additional context (user, session, data sensitivity)',
          properties: {
            user: { type: 'string' },
            session_id: { type: 'string' },
            data_classification: { type: 'string' },
          },
        },
      },
      required: ['agent_id', 'action', 'resource'],
    },
  },
  {
    name: 'evaluate_tool_call',
    description: 'Evaluate policy for a tool call. Returns permitted/denied but does NOT execute the tool — the calling agent must execute the tool itself based on the decision. Use for gating tool access with audit trail.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Unique agent identifier' },
        tool_name: { type: 'string', description: 'Name of the tool being evaluated' },
        tool_args: { type: 'object', description: 'Arguments being passed to the tool' },
        action: { type: 'string', description: 'Action mapped to the tool (e.g., tool:openai, tool:database)' },
        resource: { type: 'string', description: 'Resource being accessed by the tool' },
        context: {
          type: 'object',
          description: 'Additional context for policy evaluation',
          properties: {
            user: { type: 'string' },
            session_id: { type: 'string' },
            data_classification: { type: 'string' },
          },
        },
      },
      required: ['agent_id', 'tool_name', 'action', 'resource'],
    },
  },
  {
    name: 'register_agent',
    description: 'Register a new AI agent in the security monitoring system',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Human-readable agent name' },
        type: { type: 'string', description: 'Agent type (langchain, crewai, claude_code, openclaw, openai_agents, custom)' },
        api_key_hash: { type: 'string', description: 'Hashed API key for identification' },
        owner: { type: 'string', description: 'Owner/creator of the agent' },
        metadata: { type: 'object', description: 'Additional agent metadata' },
      },
      required: ['name', 'type'],
    },
  },
  {
    name: 'log_event',
    description: 'Log an agent action event for audit trail',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'UUID of the agent' },
        event_type: { type: 'string', description: 'Type of event (e.g., tool_call, api_request)' },
        action: { type: 'string', description: 'Action performed' },
        resource: { type: 'string', description: 'Resource accessed' },
        result: { type: 'string', enum: ['success', 'denied', 'error'], description: 'Result of the action' },
        details: { type: 'object', description: 'Additional event details' },
      },
      required: ['agent_id', 'event_type', 'result'],
    },
  },
  {
    name: 'query_compliance',
    description: 'Query compliance evidence for a specific agent and regulation',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'UUID of the agent' },
        regulation: { type: 'string', description: 'Regulation to check (gdpr, ai_act, ccpa, hipaa, finra)' },
      },
      required: ['agent_id', 'regulation'],
    },
  },
];

export interface ToolCallResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

/**
 * Handle a single MCP tool call. Pure function — takes an apiCall dependency
 * so it can be tested in-process against a running or injected API.
 */
export async function handleToolCall(
  name: string,
  args: unknown,
  apiCall: ApiCallFn
): Promise<ToolCallResult> {
  try {
    switch (name) {
      case 'gate_action': {
        const { agent_id, action, resource, context } = args as {
          agent_id: string; action: string; resource: string;
          context?: { user?: string; session_id?: string; data_classification?: string };
        };
        const result = await apiCall<{
          allowed: boolean; reason: string; certificate_id: string; evaluated_at: string;
        }>('/policy/evaluate', 'POST', { agent_id, action, resource, context });
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'evaluate_tool_call': {
        const { agent_id, tool_name, tool_args, action, resource, context } = args as {
          agent_id: string; tool_name: string; tool_args?: Record<string, unknown>;
          action: string; resource: string;
          context?: { user?: string; session_id?: string; data_classification?: string };
        };
        const evalResult = await apiCall<{
          allowed: boolean; reason: string; certificate_id: string; policy_id?: string; evaluated_at: string;
        }>('/policy/evaluate', 'POST', { agent_id, action, resource, context });

        if (!evalResult.allowed) {
          const logResult = await apiCall<{ event: { id: string } }>(
            `/agents/${agent_id}/events`, 'POST',
            {
              agent_id, event_type: 'tool_denied', action: `tool:${tool_name}`, resource,
              result: 'denied',
              details: { tool_name, tool_args, reason: evalResult.reason, certificate_id: evalResult.certificate_id },
            }
          );
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                status: 'denied', reason: evalResult.reason, certificate_id: evalResult.certificate_id,
                event_id: logResult.event.id,
                note: 'Tool execution was NOT performed. The calling agent must respect the denied decision.',
              }),
            }],
            isError: true,
          };
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'permitted', certificate_id: evalResult.certificate_id, policy_id: evalResult.policy_id,
              tool_evaluation: { tool_name, args: tool_args, permitted: true, evaluated_at: evalResult.evaluated_at },
              note: 'Policy evaluation passed. The calling agent may proceed with execution.',
            }),
          }],
        };
      }

      case 'register_agent': {
        const { name: agentName, type, api_key_hash, owner, metadata } = args as {
          name: string; type: string; api_key_hash?: string; owner?: string; metadata?: Record<string, unknown>;
        };
        const result = await apiCall<{ agent: { id: string; name: string; type: string } }>(
          '/agents', 'POST', { name: agentName, type, api_key_hash, owner, metadata }
        );
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              agent_id: result.agent.id, name: result.agent.name, type: result.agent.type,
              registered: true, created_at: new Date().toISOString(),
            }),
          }],
        };
      }

      case 'log_event': {
        const { agent_id, event_type, action, resource, result: eventResult, details } = args as {
          agent_id: string; event_type: string; action?: string; resource?: string;
          result: 'success' | 'denied' | 'error'; details?: Record<string, unknown>;
        };
        const result = await apiCall<{ event: { id: string } }>(
          `/agents/${agent_id}/events`, 'POST',
          { agent_id, event_type, action, resource, result: eventResult, details }
        );
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              event_id: result.event.id, agent_id, event_type, recorded: true, timestamp: new Date().toISOString(),
            }),
          }],
        };
      }

      case 'query_compliance': {
        const { agent_id, regulation } = args as { agent_id: string; regulation: string };
        const result = await apiCall<{
          agent_id: string; regulation: string; compliant: boolean;
          controls_satisfied: string[]; gaps: string[];
        }>(`/compliance/${agent_id}/${regulation}`, 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
        }),
      }],
      isError: true,
    };
  }
}

export async function run(): Promise<void> {
  const apiBase = process.env.API_BASE_URL || 'http://localhost:8000';
  const apiKey = process.env.API_KEY || '';
  const apiCall = createApiCall(apiBase, apiKey);

  const server = new Server(
    { name: 'ai-agent-security-monitor', version: '0.1.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MCP_TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    const { name, arguments: args } = request.params;
    const result = handleToolCall(name, args, apiCall);
    return result as unknown as { content: unknown[]; isError?: boolean };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AI Agent Security Monitor MCP Server running on stdio');
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  run().catch(console.error);
}