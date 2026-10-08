import { ScanModule } from '../types';

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  modules: ScanModule[];
  isDefault: boolean;
  organizationId: string | null;
  createdBy: string;
  createdAt: Date;
}

const BUILT_IN_PROFILES: Omit<ScanProfile, 'id' | 'createdAt'>[] = [
  {
    name: 'Quick Scan',
    description: 'Fast reconnaissance - DNS, TLS, headers, technology fingerprint. ~2 minutes.',
    modules: ['dns', 'tls', 'headers', 'technology', 'portScan'],
    isDefault: true,
    organizationId: null,
    createdBy: 'system',
  },
  {
    name: 'Full Web Assessment',
    description: 'Comprehensive web application security assessment with all attack modules.',
    modules: [
      'dns', 'tls', 'headers', 'webConfig', 'technology', 'portScan', 'osFingerprint',
      'activeVuln', 'modernAttacks', 'behavioral', 'brokenAuth', 'apiSecurity',
      'businessLogic', 'supplyChain', 'supplyChainIntel', 'sourceAnalysis',
      'cloudSecurity', 'clientSecurity', 'exploitChain', 'liveCve',
    ],
    isDefault: true,
    organizationId: null,
    createdBy: 'system',
  },
  {
    name: 'Network Pentest',
    description: 'Deep network-level assessment including nmap, nikto, nuclei scans.',
    modules: [
      'dns', 'tls', 'portScan', 'osFingerprint', 'dnsDeep', 'tlsDeep',
      'kaliTools', 'linuxSystem', 'windowsSystem', 'networkPentest',
    ],
    isDefault: true,
    organizationId: null,
    createdBy: 'system',
  },
  {
    name: 'API Security',
    description: 'Focused API testing - authentication, authorization, injection, rate limiting.',
    modules: [
      'dns', 'tls', 'headers', 'technology', 'portScan',
      'apiSecurity', 'brokenAuth', 'activeVuln', 'modernAttacks',
    ],
    isDefault: true,
    organizationId: null,
    createdBy: 'system',
  },
  {
    name: 'PCI DSS Scan',
    description: 'Modules relevant to PCI DSS compliance requirements.',
    modules: [
      'dns', 'tls', 'headers', 'portScan', 'kaliTools',
      'activeVuln', 'brokenAuth', 'apiSecurity', 'cloudSecurity',
    ],
    isDefault: true,
    organizationId: null,
    createdBy: 'system',
  },
];

const customProfiles = new Map<string, ScanProfile>();
let nextCustomId = 1;

export async function getProfiles(organizationId: string): Promise<ScanProfile[]> {
  const builtIn = BUILT_IN_PROFILES.map((p, i) => ({
    ...p,
    id: 'builtin-' + i,
    createdAt: new Date(),
  }));

  const orgProfiles = Array.from(customProfiles.values())
    .filter(p => p.organizationId === organizationId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

  return [...builtIn, ...orgProfiles];
}

export async function createProfile(
  organizationId: string,
  createdBy: string,
  name: string,
  description: string,
  modules: ScanModule[]
): Promise<ScanProfile> {
  const id = `custom-${nextCustomId++}`;
  const profile: ScanProfile = {
    id,
    name,
    description,
    modules,
    isDefault: false,
    organizationId,
    createdBy,
    createdAt: new Date(),
  };

  customProfiles.set(id, profile);
  return profile;
}

export async function deleteProfile(id: string, organizationId: string): Promise<void> {
  const profile = customProfiles.get(id);
  if (profile && profile.organizationId === organizationId) {
    customProfiles.delete(id);
  }
}
