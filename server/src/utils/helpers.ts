import { v4 as uuidv4 } from 'uuid';

export const generateId = (): string => uuidv4();

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const sanitizeString = (input: string): string =>
  input.trim().replace(/<[^>]*>/g, '').replace(/[<>]/g, '');

export const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
};

export const formatDate = (date: Date): string => date.toISOString();

export const maskEmail = (email: string): string => {
  const [localPart, domain] = email.split('@');
  if (localPart.length <= 2) {
    return `${localPart[0]}***@${domain}`;
  }
  const masked = `${localPart[0]}***${localPart[localPart.length - 1]}`;
  return `${masked}@${domain}`;
};
