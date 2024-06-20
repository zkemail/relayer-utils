const { join } = require("path");

// Function to determine the correct binary file based on architecture
function getBinaryPath() {
  const arch = process.arch;
  let binaryName;

  switch (arch) {
    case "x64":
      binaryName = "binary-x64.node";
      break;
    case "arm64":
      binaryName = "binary-arm64.node";
      break;
    // Add more cases as needed
    default:
      throw new Error(`Unsupported architecture: ${arch}`);
  }

  return join(__dirname, "bin", binaryName);
}

// Load the appropriate binary for the current architecture
const binaryPath = getBinaryPath();
const binary = require(binaryPath);

module.exports = binary;
