// types/env.d.ts

namespace NodeJS {
  interface ProcessEnv {
    LOG_DIRECTORY: string;
    QUARANTINE_INFECTED: string;
    REMOVE_INFECTED: string;
    CLAMSCAN_PATH: string;
    CLAMD_SCAN_ACTIVE: string;
    CLAMD_SCAN_HOST: string;
    CLAMD_SCAN_PORT: string;
    CLAMAV_DB: string;
    PREFERENCE: string;
    // Add any additional environment variables here
  }
}
