// server.ts

import NodeClam from "clamscan";
import fs from "fs";
import path from "path";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import winston from "winston";
import dotenvSafe from "dotenv-safe";

// Load and validate environment variables from .env file
dotenvSafe.config({
  example: "./.env.example",
  path: "./.env",
});

// Configure Logging with Winston
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp({
      format: "YYYY-MM-DD HH:mm:ss",
    }),
    winston.format.printf(
      (info) =>
        `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`
    )
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIRECTORY as string, "scan.log"),
    }),
  ],
});

// Parse Command-Line Arguments with Types
const argv = yargs(hideBin(process.argv))
  .usage("Usage: $0 -f [files] -d [directories]")
  .option("f", {
    alias: "files",
    describe: "File(s) to scan",
    type: "array",
  })
  .option("d", {
    alias: "directories",
    describe: "Directory(ies) to scan recursively",
    type: "array",
  })
  .option("q", {
    alias: "quarantine",
    describe: "Quarantine infected files",
    type: "boolean",
    default: process.env.QUARANTINE_INFECTED === "true",
  })
  .option("r", {
    alias: "remove",
    describe: "Remove infected files",
    type: "boolean",
    default: process.env.REMOVE_INFECTED === "true",
  })
  .help()
  .alias("help", "h").argv as unknown as {
  files?: string[];
  directories?: string[];
  quarantine: boolean;
  remove: boolean;
};

// Validate Input
if (
  (!argv.files || argv.files.length === 0) &&
  (!argv.directories || argv.directories.length === 0)
) {
  logger.error("No files or directories specified for scanning.");
  yargs.showHelp();
  process.exit(1);
}

// Initialize ClamScan Configuration
const ClamScan = new NodeClam().init({
  removeInfected: argv.remove, // If true, removes infected files
  quarantineInfected: argv.quarantine, // If true, quarantines infected files
  quarantinePath: argv.quarantine ? "./quarantine" : undefined, // Specify quarantine directory
  scanLog: path.join(process.env.LOG_DIRECTORY as string, "scan.log"), // Path to a writable log file
  debugMode: false, // Whether or not to log info/debug/error msgs to the console
  scanRecursively: true, // If true, deep scan folders recursively
  clamscan: {
    path: process.env.CLAMSCAN_PATH as string, // Path to clamscan binary on your server
    scanArchives: true, // If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
    active: false, // Disable local clamscan since we're using remote clamdscan
    db: process.env.CLAMAV_DB || "/var/lib/clamav/", // Path to virus database
  },
  clamdscan: {
    active: process.env.CLAMD_SCAN_ACTIVE === "true", // Enable clamdscan based on config
    host: process.env.CLAMD_SCAN_HOST || "127.0.0.1", // Remote clamd host
    port: parseInt(process.env.CLAMD_SCAN_PORT as string, 10) || 3310, // Remote clamd port
    timeout: 300000, // 5 minutes
    path: "/usr/bin/clamdscan", // Path to clamdscan binary on your server
    configFile: "/etc/clamav/clamd.conf", // Path to clamd configuration file
    multiscan: true, // Enable multi-threaded scanning for better performance
    reloadDb: false, // Do not reload DB each scan (handled by freshclam)
    bypassTest: false, // Ensure socket availability
  },
  preference: process.env.PREFERENCE || "clamdscan", // Use clamdscan by default
});

// Ensure Quarantine Directory Exists
if (argv.quarantine && !fs.existsSync("./quarantine")) {
  fs.mkdirSync("./quarantine", { recursive: true });
  logger.info("Created quarantine directory at ./quarantine");
}

// Helper Function to Resolve Absolute Paths
const resolvePath = (p: string): string => path.resolve(process.cwd(), p);

// Collect Files to Scan
const collectFiles = (files?: string[], directories?: string[]): string[] => {
  const collectedFiles = new Set<string>();

  // Add specified files
  if (files) {
    files.forEach((file) => {
      const absPath = resolvePath(file);
      if (fs.existsSync(absPath) && fs.lstatSync(absPath).isFile()) {
        collectedFiles.add(absPath);
      } else {
        logger.warn(`File not found or is not a file: ${absPath}`);
      }
    });
  }

  // Add files from specified directories recursively
  if (directories) {
    directories.forEach((dir) => {
      const absDir = resolvePath(dir);
      if (fs.existsSync(absDir) && fs.lstatSync(absDir).isDirectory()) {
        const walk = (dirPath: string) => {
          fs.readdirSync(dirPath).forEach((entry) => {
            const fullPath = path.join(dirPath, entry);
            if (fs.lstatSync(fullPath).isDirectory()) {
              walk(fullPath);
            } else if (fs.lstatSync(fullPath).isFile()) {
              collectedFiles.add(fullPath);
            }
          });
        };
        walk(absDir);
      } else {
        logger.warn(`Directory not found or is not a directory: ${absDir}`);
      }
    });
  }

  return Array.from(collectedFiles);
};

// Main Function to Perform Scans
const performScan = async () => {
  try {
    const filesToScan = collectFiles(argv.files, argv.directories);

    if (filesToScan.length === 0) {
      logger.info("No valid files found to scan.");
      process.exit(0);
    }

    logger.info(`Starting scan of ${filesToScan.length} file(s)...`);

    const cs = await ClamScan;

    for (const file of filesToScan) {
      try {
        const { isInfected, viruses } = await cs.isInfected(file);
        if (isInfected) {
          logger.warn(`${file} IS INFECTED! Viruses: ${viruses.join(", ")}`);

          // Handle Quarantine or Removal
          if (argv.quarantine) {
            const quarantinePath = path.join(
              "./quarantine",
              path.basename(file)
            );
            fs.renameSync(file, quarantinePath);
            logger.info(`Moved ${file} to quarantine.`);
          }

          if (argv.remove) {
            fs.unlinkSync(file);
            logger.info(`Removed infected file: ${file}`);
          }
        } else {
          logger.info(`${file} is OK!`);
        }
      } catch (err: any) {
        logger.error(`Error scanning ${file}: ${err.message}`);
      }
    }

    logger.info("Scan completed.");
  } catch (error: any) {
    logger.error(`Error initializing ClamScan: ${error.message}`);
  }
};

// Execute the Scan
performScan();
