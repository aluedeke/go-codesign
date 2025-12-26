#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const PACKAGE_VERSION = require('../package.json').version;
const REPO = 'aluedeke/go-codesign';
const BINARY_NAME = 'go-codesign';

function getPlatformInfo() {
  const platform = process.platform;
  const arch = process.arch;

  // Map Node.js platform/arch to Go's GOOS/GOARCH
  const platformMap = {
    darwin: 'darwin',
    linux: 'linux',
    win32: 'windows',
  };

  const archMap = {
    x64: 'amd64',
    arm64: 'arm64',
  };

  const goos = platformMap[platform];
  const goarch = archMap[arch];

  if (!goos || !goarch) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }

  return { goos, goarch };
}

function getBinaryName(goos) {
  return goos === 'windows' ? `${BINARY_NAME}.exe` : BINARY_NAME;
}

function getDownloadUrl(version, goos, goarch) {
  const ext = goos === 'windows' ? '.zip' : '.tar.gz';
  const assetName = `go-codesign_${version}_${goos}_${goarch}${ext}`;
  return `https://github.com/${REPO}/releases/download/v${version}/${assetName}`;
}

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    const makeRequest = (url, redirectCount = 0) => {
      if (redirectCount > 5) {
        reject(new Error('Too many redirects'));
        return;
      }

      https.get(url, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          makeRequest(response.headers.location, redirectCount + 1);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: ${response.statusCode}`));
          return;
        }

        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve(Buffer.concat(chunks)));
        response.on('error', reject);
      }).on('error', reject);
    };

    makeRequest(url);
  });
}

async function extractTarGz(buffer, destDir) {
  const tmpFile = path.join(destDir, 'tmp.tar.gz');
  fs.writeFileSync(tmpFile, buffer);

  try {
    execSync(`tar -xzf "${tmpFile}" -C "${destDir}"`, { stdio: 'pipe' });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function extractZip(buffer, destDir) {
  const tmpFile = path.join(destDir, 'tmp.zip');
  fs.writeFileSync(tmpFile, buffer);

  try {
    execSync(`unzip -o "${tmpFile}" -d "${destDir}"`, { stdio: 'pipe' });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function install() {
  try {
    const { goos, goarch } = getPlatformInfo();
    const binDir = path.join(__dirname, '..', 'bin');
    const binaryName = getBinaryName(goos);
    const binaryPath = path.join(binDir, binaryName);

    // Check if binary already exists
    if (fs.existsSync(binaryPath)) {
      console.log(`go-codesign binary already exists at ${binaryPath}`);
      return;
    }

    // Ensure bin directory exists
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }

    const url = getDownloadUrl(PACKAGE_VERSION, goos, goarch);
    console.log(`Downloading go-codesign v${PACKAGE_VERSION} for ${goos}/${goarch}...`);
    console.log(`URL: ${url}`);

    const buffer = await downloadFile(url);
    console.log(`Downloaded ${buffer.length} bytes`);

    // Extract based on platform
    if (goos === 'windows') {
      await extractZip(buffer, binDir);
    } else {
      await extractTarGz(buffer, binDir);
    }

    // Make binary executable on Unix
    if (goos !== 'windows') {
      fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`Successfully installed go-codesign to ${binaryPath}`);
  } catch (error) {
    console.error(`Failed to install go-codesign: ${error.message}`);
    console.error('');
    console.error('You can manually download the binary from:');
    console.error(`https://github.com/${REPO}/releases`);
    console.error('');
    console.error('Or install via Go:');
    console.error('  go install github.com/aluedeke/go-codesign@latest');
    process.exit(1);
  }
}

install();
