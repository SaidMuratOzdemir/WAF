export interface Site {
    port: number;
    name: string;
    frontend_url: string;
    backend_url: string;
    xss_enabled: boolean;
    sql_enabled: boolean;
}
