export type EntityType =
  | "change"
  | "division"
  | "service"
  | "server"
  | "application"
  | "capability"
  | "ip"
  | "risk"
  | "time_window";

export type ConnectionType =
  | "belongs_to"
  | "impacts"
  | "touches"
  | "uses_ip"
  | "affects"
  | "depends_on"
  | "rated_as"
  | "scheduled_in";

export interface BaseEntity {
  id: string;
  type: EntityType;
  name: string;
  description?: string;
  shortDescription?: string;
  startDate?: string;
  endDate?: string;
  division?: string;
  service?: string;
  risk?: string;
  aiScore?: number | null;
  timeWindow?: string;
  attributes?: Record<string, unknown>;
  notes?: string;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
}

export interface Connection {
  id: string;
  type: ConnectionType;
  fromId: string;
  toId: string;
  createdAt: string;
}

export interface GraphResponse {
  nodes: BaseEntity[];
  links: Connection[];
}
