export interface HostBridge {
    getKV(key: string): string;
    setKV(key: string, value: string): void;
    resolveDNS(domain: string): string[];
}

export interface Finding {
    name: string;
    description: string;
}

export class ValayamSDK {
    private host: HostBridge;

    constructor(host: HostBridge) {
        this.host = host;
    }

    public getKV(key: string): string {
        return this.host.getKV(key);
    }

    public setKV(key: string, value: string): void {
        this.host.setKV(key, value);
    }

    public resolveDNS(domain: string): string[] {
        return this.host.resolveDNS(domain);
    }

    public reportFinding(finding: Finding): void {
        // Implement communication with WASM host
        throw new Error("reportFinding not implemented");
    }
}
