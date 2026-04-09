import { EventEmitter } from 'events';

export interface SecurityScarletConfig {
  apiUrl: string;
  apiKey: string;
  eventBusUrl: string;
  pollIntervalMs: number;
}

export interface ScarletEvent {
  type: string;
  source: string;
  timestamp: Date;
  data: Record<string, unknown>;
}

export interface ScarletAnomaly {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  detected_at: Date;
  agent_id?: string;
}

const DEFAULT_CONFIG: SecurityScarletConfig = {
  apiUrl: process.env.SCARLET_API_URL || 'http://localhost:9000',
  apiKey: process.env.SCARLET_API_KEY || '',
  eventBusUrl: process.env.SCARLET_EVENT_BUS_URL || 'http://localhost:9001',
  pollIntervalMs: 30000,
};

export class SecurityScarletIntegration extends EventEmitter {
  private config: SecurityScarletConfig;
  private intervalId: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<SecurityScarletConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async forwardEvent(event: {
    agent_id: string;
    event_type: string;
    action?: string;
    resource?: string;
    result: string;
    details: Record<string, unknown>;
    created_at: Date;
  }): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.apiUrl}/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify({
          source: 'ai-agent-security-monitor',
          type: event.event_type,
          agent_id: event.agent_id,
          action: event.action,
          resource: event.resource,
          result: event.result,
          data: event.details,
          timestamp: event.created_at.toISOString(),
        }),
      });

      return response.ok;
    } catch (error) {
      this.emit('forward_error', error);
      return false;
    }
  }

  async fetchAnomalies(): Promise<ScarletAnomaly[]> {
    try {
      const response = await fetch(`${this.config.apiUrl}/anomalies`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
      });

      if (!response.ok) return [];

      const data = await response.json() as { anomalies: ScarletAnomaly[] };
      return data.anomalies || [];
    } catch {
      return [];
    }
  }

  startAnomalyPolling(): void {
    this.intervalId = setInterval(async () => {
      try {
        const anomalies = await this.fetchAnomalies();
        for (const anomaly of anomalies) {
          this.emit('anomaly', anomaly);
        }
      } catch (error) {
        this.emit('poll_error', error);
      }
    }, this.config.pollIntervalMs);
  }

  stopAnomalyPolling(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  async checkConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.apiUrl}/health`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}

export const scarletIntegration = new SecurityScarletIntegration();

if (import.meta.url === `file://${process.argv[1]}`) {
  const integration = new SecurityScarletIntegration();

  integration.on('anomaly', (anomaly) => {
    console.log('Received anomaly from SecurityScarletAI:', anomaly);
  });

  integration.startAnomalyPolling();
  console.log('SecurityScarletAI integration started');

  setTimeout(() => integration.stopAnomalyPolling(), 300000);
}
