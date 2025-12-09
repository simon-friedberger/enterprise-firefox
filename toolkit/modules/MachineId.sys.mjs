/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  Subprocess: "resource://gre/modules/Subprocess.sys.mjs",
});

async function sha256Hex(message) {
  let hasher = Cc["@mozilla.org/security/hash;1"].createInstance(
    Ci.nsICryptoHash
  );
  hasher.init(hasher.SHA256);
  let encoder = new TextEncoder();
  let data = encoder.encode(message);
  hasher.update(data, data.length);
  let hash = hasher.finish(false);
  return Array.from(hash, c =>
    c.charCodeAt(0).toString(16).padStart(2, "0")
  ).join("");
}

async function getLinuxMachineId() {
  try {
    let content = await IOUtils.readUTF8("/etc/machine-id");
    return content.trim();
  } catch (e) {
    console.error("MachineId: Failed to read /etc/machine-id:", e);
    return null;
  }
}

async function getWindowsMachineId() {
  try {
    const { WindowsRegistry } = ChromeUtils.importESModule(
      "resource://gre/modules/WindowsRegistry.sys.mjs"
    );
    let machineGuid = WindowsRegistry.readRegKey(
      Ci.nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE,
      "SOFTWARE\\Microsoft\\Cryptography",
      "MachineGuid"
    );
    return machineGuid || null;
  } catch (e) {
    console.error("MachineId: Failed to read Windows MachineGuid:", e);
    return null;
  }
}

async function getMacMachineId() {
  try {
    let proc = await lazy.Subprocess.call({
      command: "/usr/sbin/ioreg",
      arguments: ["-rd1", "-c", "IOPlatformExpertDevice"],
    });

    let output = "";
    let chunk;
    while ((chunk = await proc.stdout.readString())) {
      output += chunk;
    }
    await proc.wait();

    // Parse IOPlatformSerialNumber from output
    let match = output.match(/"IOPlatformSerialNumber"\s*=\s*"([^"]+)"/);
    if (match) {
      return match[1];
    }

    // Fallback: try IOPlatformUUID
    match = output.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
    if (match) {
      return match[1];
    }

    return null;
  } catch (e) {
    console.error("MachineId: Failed to get macOS machine ID:", e);
    return null;
  }
}

let cachedRawId = null;
let cachedHashedId = null;

export const MachineId = {
  async getRawId() {
    if (cachedRawId !== null) {
      return cachedRawId;
    }

    let id = null;
    switch (AppConstants.platform) {
      case "linux":
        id = await getLinuxMachineId();
        break;
      case "win":
        id = await getWindowsMachineId();
        break;
      case "macosx":
        id = await getMacMachineId();
        break;
      default:
        console.warn("MachineId: Unsupported platform:", AppConstants.platform);
    }

    cachedRawId = id;
    return id;
  },

  async getHashedId() {
    if (cachedHashedId !== null) {
      return cachedHashedId;
    }

    let rawId = await this.getRawId();
    if (!rawId) {
      return null;
    }

    cachedHashedId = await sha256Hex(rawId);
    return cachedHashedId;
  },

  clearCache() {
    cachedRawId = null;
    cachedHashedId = null;
  },
};
