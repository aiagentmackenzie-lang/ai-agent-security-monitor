import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const API_BASE = process.env.API_BASE_URL || 'http://localhost:8000';

async function apiCall<T>(endpoint: string, method: string, body?: unknown): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API error ${response.status}: ${error}`);
  }

  return response.json() as Promise<T>;
}

const server = new Server(
  {
    name: 'ai-agent-security-monitor',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'gate_action',
        description: 'Evaluate a policy decision before agent action execution. Returns allow/deny with signed certificate.',
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
        name: 'enforced_tool_call',
        description: 'Strong enforcement tier: Proxy a tool call through policy evaluation. Blocks if denied, executes if permitted. Use this for critical tool access control.',
        inputSchema: {
          type: 'object',
          properties: {
            agent_id: { type: 'string', description: 'Unique agent identifier' },
            tool_name: { type: 'string', description: 'Name of the tool being proxied' },
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
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'gate_action': {
        const { agent_id, action, resource, context } = args as {
          agent_id: string;
          action: string;
          resource: string;
          context?: { user?: string; session_id?: string; data_classification?: string };
        };

        const result = await apiCall<{
          allowed: boolean;
          reason: string;
          certificate_id: string;
          evaluated_at: string;
        }>('/policy/evaluate', 'POST', {
          agent_id,
          action,
          resource,
          context,
        });

        return {
          content: [{ type: 'text', text: JSON.stringify(result) }],
        };
      }

      case 'enforced_tool_call': {
        const { agent_id, tool_name, tool_args, action, resource, context } = args as {
          agent_id: string;
          tool_name: string;
          tool_args?: Record<string, unknown>;
          action: string;
          resource: string;
          context?: { user?: string; session_id?: string; data_classification?: string };
        };

        const evalResult = await apiCall<{
          allowed: boolean;
          reason: string;
          certificate_id: string;
          policy_id?: string;
          evaluated_at: string;
        }>('/policy/evaluate', 'POST', {
          agent_id,
          action,
          resource,
          context,
        });

        if (!evalResult.allowed) {
          const logResult = await apiCall<{ event: { id: string } }>(
            `/agents/${agent_id}/events`,
            'POST',
            {
              agent_id,
              event_type: 'tool_denied',
              action: `tool:${tool_name}`,
              resource,
              result: 'denied',
              details: {
                tool_name,
                tool_args,
                reason: evalResult.reason,
                certificate_id: evalResult.certificate_id,
              },
            }
          );

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  status: 'denied',
                  reason: evalResult.reason,
                  certificate_id: evalResult.certificate_id,
                  event_id: logResult.event.id,
                }),
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'permitted',
                certificate_id: evalResult.certificate_id,
                policy_id: evalResult.policy_id,
                tool_execution: {
                  tool_name,
                  args: tool_args,
                  permitted: true,
                  evaluated_at: evalResult.evaluated_at,
                },
              }),
            },
          ],
        };
      }

      case 'register_agent': {
        const { name, type, api_key_hash, owner, metadata } = args as {
          name: string;
          type: string;
          api_key_hash?: string;
          owner?: string;
          metadata?: Record<string, unknown>;
        };

        const result = await apiCall<{ agent: { id: string; name: string; type: string; status: string } }>(
          '/agents',
          'POST',
          { name, type, api_key_hash, owner, metadata }
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                agent_id: result.agent.id,
                name: result.agent.name,
                type: result.agent.type,
                status: 'registered',
                created_at: new Date().toISOString(),
              }),
            },
          ],
        };
      }

      case 'log_event': {
        const { agent_id, event_type, action, resource, result: eventResult, details } = args as {
          agent_id: string;
          event_type: string;
          action?: string;
          resource?: string;
          result: 'success' | 'denied' | 'error';
          details?: Record<string, unknown>;
        };

        const result = await apiCall<{ event: { id: string } }>(
          `/agents/${agent_id}/events`,
          'POST',
          { agent_id, event_type, action, resource, result: eventResult, details }
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                event_id: result.event.id,
                agent_id,
                event_type,
                recorded: true,
                timestamp: new Date().toISOString(),
              }),
            },
          ],
        };
      }

      case 'query_compliance': {
        const { agent_id, regulation } = args as {
          agent_id: string;
          regulation: string;
        };

        const result = await apiCall<{
          agent_id: string;
          regulation: string;
          compliant: boolean;
          controls_satisfied: string[];
          gaps: string[];
        }>(`/compliance/${agent_id}/${regulation}`, 'GET');

        return {
          content: [{ type: 'text', text: JSON.stringify(result) }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString(),
          }),
        },
      ],
      isError: true,
    };
  }
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AI Agent Security Monitor MCP Server running on stdio');
}

run().catch(console.error);
