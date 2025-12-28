#!/usr/bin/env node

const path = require('path');
const childProcess = require('child_process');
const fs = require('fs');

// Mapping from Node's `process.arch` to Golang's `$GOARCH`
const ARCH_MAPPING = {
  x64: 'amd64',
  arm64: 'arm64',
};

// Mapping between Node's `process.platform` to Golang's
const PLATFORM_MAPPING = {
  darwin: 'darwin',
  linux: 'linux',
  win32: 'windows',
};

function findBinary() {
  const binaryName = `go-codesign${process.platform === 'win32' ? '.exe' : ''}`;
  const binaryRoot = path.join(__dirname, 'dist');
  const goPlatform = PLATFORM_MAPPING[process.platform];
  const goArch = ARCH_MAPPING[process.arch];

  if (!goPlatform || !goArch) {
    throw new Error(
      `Unsupported platform: ${process.platform}@${process.arch}`
    );
  }

  const folderName = `${goPlatform}_${goArch}`;
  const fullPath = path.join(binaryRoot, folderName, binaryName);

  if (!fs.existsSync(fullPath)) {
    throw new Error(
      `Binary not found at '${fullPath}'. Supported platforms: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64`
    );
  }

  return fullPath;
}

function main() {
  const binaryPath = findBinary();
  const result = childProcess.spawnSync(binaryPath, process.argv.slice(2), {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
  });

  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }

  process.exit(result.status || 0);
}

main();
