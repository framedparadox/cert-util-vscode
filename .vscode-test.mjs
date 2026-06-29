import { existsSync } from 'node:fs';
import { defineConfig } from '@vscode/test-cli';

const configuredPath = process.env.VSCODE_EXECUTABLE_PATH;
const macOsApplicationPath = '/Applications/Visual Studio Code.app/Contents/MacOS/Code';
let localInstallationPath;
if (configuredPath && existsSync(configuredPath)) {
    localInstallationPath = configuredPath;
} else if (existsSync(macOsApplicationPath)) {
    localInstallationPath = macOsApplicationPath;
}

export default defineConfig({
    files: 'out/test/**/*.test.js',
    ...(localInstallationPath ? { useInstallation: { fromPath: localInstallationPath } } : {}),
});
