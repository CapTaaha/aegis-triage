import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

const blockedAddresses = new BlockList();

for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) blockedAddresses.addSubnet(network, prefix, "ipv4");

for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001::", 23],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) blockedAddresses.addSubnet(network, prefix, "ipv6");

export type PublicAddress = { address: string; family: 4 | 6 };

export const isPublicAddress = (address: string) => {
  const family = isIP(address);
  return family !== 0 && !blockedAddresses.check(address, family === 4 ? "ipv4" : "ipv6");
};

export const resolvePublicAddress = async (hostname: string): Promise<PublicAddress> => {
  if (!hostname || hostname.endsWith(".")) hostname = hostname.slice(0, -1);
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error("Private, local, reserved, multicast, and link-local addresses are blocked.");
  }
  const selected = addresses[0];
  return { address: selected.address, family: selected.family as 4 | 6 };
};
