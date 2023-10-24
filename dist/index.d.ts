declare const decryptPDF: (pdf: string | Uint8Array | ArrayBuffer, ownerPassword: string) => Promise<Uint8Array>;

export { decryptPDF };
