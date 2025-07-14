export interface Pattern {
  id: number;
  pattern: string;
  type: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface PatternCreate {
  pattern: string;
  type: string;
  description?: string;
}

export interface PatternUpdate {
  pattern?: string;
  type?: string;
  description?: string;
} 