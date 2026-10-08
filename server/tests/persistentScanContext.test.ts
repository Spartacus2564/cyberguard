jest.mock('../src/lib/redis', () => ({
  __esModule: true,
  default: {
    rpush: jest.fn(),
    ltrim: jest.fn(),
    expire: jest.fn(),
  },
}));

import {
  getScanContext,
  initializeScanContext,
  withScanContext,
} from '../src/engine/modules/persistentScanContext';

describe('persistent scan context', () => {
  it('keeps overlapping scans isolated across async boundaries', async () => {
    const runScan = (scanId: string, domain: string, delay: number) =>
      withScanContext(async () => {
        initializeScanContext(domain, 'web', domain, scanId);
        await new Promise(resolve => setTimeout(resolve, delay));
        const context = getScanContext();
        return { scanId: context?.scanId, domain: context?.domain };
      });

    const [first, second] = await Promise.all([
      runScan('scan-first', 'first.example', 10),
      runScan('scan-second', 'second.example', 0),
    ]);

    expect(first).toEqual({ scanId: 'scan-first', domain: 'first.example' });
    expect(second).toEqual({ scanId: 'scan-second', domain: 'second.example' });
  });
});