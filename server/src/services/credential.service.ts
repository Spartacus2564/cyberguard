import prisma from '../lib/prisma';
import crypto from 'crypto';
import logger from '../utils/logger';

const ENCRYPTION_KEY = crypto.scryptSync(
  process.env.JWT_SECRET || 'dev-key-change-me',
  'cyberguard-credential-salt',
  32
);

export interface StoredCredential {
  id: string;
  name: string;
  type: 'basic' | 'form' | 'cookie' | 'header';
  username?: string;
  password?: string;
  cookies?: string;
  headers?: Record<string, string>;
  loginUrl?: string;
  loginSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  successIndicator?: string;
  createdAt: Date;
}

function encrypt(text: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText: string): string {
  const [ivHex, encrypted] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export async function storeCredential(
  engagementId: string,
  name: string,
  type: 'basic' | 'form' | 'cookie' | 'header',
  data: {
    username?: string;
    password?: string;
    cookies?: string;
    headers?: Record<string, string>;
    loginUrl?: string;
    loginSelector?: string;
    passwordSelector?: string;
    submitSelector?: string;
    successIndicator?: string;
  }
): Promise<StoredCredential> {
  const encryptedData: Record<string, unknown> = {
    name,
    type,
    engagementId,
    loginUrl: data.loginUrl,
    loginSelector: data.loginSelector,
    passwordSelector: data.passwordSelector,
    submitSelector: data.submitSelector,
    successIndicator: data.successIndicator,
  };

  if (data.username) encryptedData.username = encrypt(data.username);
  if (data.password) encryptedData.password = encrypt(data.password);
  if (data.cookies) encryptedData.cookies = encrypt(data.cookies);
  if (data.headers) {
    const encryptedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(data.headers)) {
      encryptedHeaders[k] = encrypt(v);
    }
    encryptedData.headers = encryptedHeaders;
  }

  const stored = await prisma.storedCredential.create({
    data: encryptedData as never,
  });

  logger.info('[Credentials] Stored credential: ' + name + ' for engagement: ' + engagementId);

  return {
    id: stored.id,
    name: stored.name,
    type: stored.type as StoredCredential['type'],
    username: data.username,
    password: data.password,
    cookies: data.cookies,
    headers: data.headers,
    loginUrl: stored.loginUrl || undefined,
    loginSelector: stored.loginSelector || undefined,
    passwordSelector: stored.passwordSelector || undefined,
    submitSelector: stored.submitSelector || undefined,
    successIndicator: stored.successIndicator || undefined,
    createdAt: stored.createdAt,
  };
}

export async function getCredential(
  credentialId: string,
  engagementId: string
): Promise<StoredCredential | null> {
  const stored = await prisma.storedCredential.findFirst({
    where: { id: credentialId, engagementId },
  });
  if (!stored) return null;

  return {
    id: stored.id,
    name: stored.name,
    type: stored.type as StoredCredential['type'],
    username: stored.username ? decrypt(stored.username) : undefined,
    password: stored.password ? decrypt(stored.password) : undefined,
    cookies: stored.cookies ? decrypt(stored.cookies) : undefined,
    headers: stored.headers
      ? Object.fromEntries(
          Object.entries(stored.headers as Record<string, string>).map(([k, v]) => [
            k,
            decrypt(v),
          ])
        )
      : undefined,
    loginUrl: stored.loginUrl || undefined,
    loginSelector: stored.loginSelector || undefined,
    passwordSelector: stored.passwordSelector || undefined,
    submitSelector: stored.submitSelector || undefined,
    successIndicator: stored.successIndicator || undefined,
    createdAt: stored.createdAt,
  };
}

export async function deleteCredential(
  credentialId: string,
  engagementId: string
): Promise<void> {
  await prisma.storedCredential.deleteMany({
    where: { id: credentialId, engagementId },
  });
}

export async function listCredentials(
  engagementId: string
): Promise<StoredCredential[]> {
  const stored = await prisma.storedCredential.findMany({
    where: { engagementId },
    orderBy: { createdAt: 'desc' },
  });

  return stored.map((s) => ({
    id: s.id,
    name: s.name,
    type: s.type as StoredCredential['type'],
    loginUrl: s.loginUrl || undefined,
    loginSelector: s.loginSelector || undefined,
    passwordSelector: s.passwordSelector || undefined,
    submitSelector: s.submitSelector || undefined,
    successIndicator: s.successIndicator || undefined,
    createdAt: s.createdAt,
  }));
}
