/**
 * Version configuration for DNSniper Frontend
 * Reads version information from the local version.json file
 */

// Import the version configuration from the local copy in src/
// This will be bundled during build time
import versionData from './version.json';

export const VERSION_INFO = versionData;
export const VERSION = versionData.version;
export const APP_NAME = versionData.name;
export const GITHUB_URL = versionData.github;
export const DESCRIPTION = versionData.description;
export const LICENSE = versionData.license;

// Export as default for easy importing
const versionConfig = {
  version: VERSION,
  name: APP_NAME,
  github: GITHUB_URL,
  description: DESCRIPTION,
  license: LICENSE,
  ...versionData
};

export default versionConfig; 