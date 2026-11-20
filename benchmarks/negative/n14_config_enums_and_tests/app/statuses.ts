export const invoiceStatuses = ["draft", "open", "paid", "void"] as const;

export type InvoiceStatus = (typeof invoiceStatuses)[number];

export const planCatalog = {
  free: { monthlyCents: 0, seats: 1, requests: 1000 },
  pro: { monthlyCents: 2900, seats: 10, requests: 100000 },
  enterprise: { monthlyCents: 9900, seats: 100, requests: 1000000 },
} as const;

export const dnsNamespaceUuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

export function planForCode(code: keyof typeof planCatalog) {
  return planCatalog[code];
}

export function isInvoiceStatus(value: string): value is InvoiceStatus {
  return (invoiceStatuses as readonly string[]).includes(value);
}
