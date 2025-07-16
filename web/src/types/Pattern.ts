export enum PatternType {
  XSS = 'xss',
  SQL = 'sql',
  CUSTOM = 'custom',
}

export interface Pattern {
  id: number;
  pattern: string;
  type: PatternType;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface PatternCreate {
  pattern: string;
  type: PatternType;
  description?: string;
}

export interface PatternUpdate {
  pattern?: string;
  type?: PatternType;
  description?: string;
} 