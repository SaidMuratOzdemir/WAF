export interface Site {
    id: number;
    port: number;
    host: string;
    name: string;
    frontend_url: string;
    backend_url: string;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
}

export interface SiteCreate {
    port: number;
    host: string;
    name: string;
    frontend_url: string;
    backend_url: string;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
}
