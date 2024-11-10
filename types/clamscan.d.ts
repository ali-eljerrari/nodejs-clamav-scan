// types/clamscan.d.ts

declare module "clamscan" {
  export interface ClamScanOptions {
    removeInfected: boolean;
    quarantineInfected: boolean;
    quarantinePath?: string;
    scanLog: string;
    debugMode: boolean;
    scanRecursively: boolean;
    clamscan: {
      path: string;
      scanArchives: boolean;
      active: boolean;
      db: string;
    };
    clamdscan: {
      active: boolean;
      host: string;
      port: number;
      timeout: number;
      path: string;
      configFile: string;
      multiscan: boolean;
      reloadDb: boolean;
      bypassTest: boolean;
    };
    preference: string;
  }

  export interface ScanResult {
    isInfected: boolean;
    viruses: string[];
  }

  export interface ClamScanInstance {
    isInfected(file: string): Promise<ScanResult>;
  }

  export default class NodeClam {
    init(options: ClamScanOptions): Promise<ClamScanInstance>;
  }
}
