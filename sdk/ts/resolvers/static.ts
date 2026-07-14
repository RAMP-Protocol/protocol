// The static named key resolver face — a thin in-memory map satisfying the
// RequestKeyResolver-shaped `resolve(keyid) -> Promise<Uint8Array | undefined>` plus a
// `put` for dynamic/test seeding. Mirrors the Go NewStaticKeyResolver: a plain
// unknown key is `undefined` (the fall-through miss), never a thrown error.

/** The static key face. */
export interface StaticKeyResolver {
  resolve(keyid: string): Promise<Uint8Array | undefined>;
  put(keyid: string, pub: Uint8Array): void;
}

/** Return a resolver seeded with `keys` (copied). */
export function createStaticKeyResolver(keys: Record<string, Uint8Array> = {}): StaticKeyResolver {
  const map = new Map<string, Uint8Array>(Object.entries(keys));
  return {
    resolve(keyid: string): Promise<Uint8Array | undefined> {
      return Promise.resolve(map.get(keyid));
    },
    put(keyid: string, pub: Uint8Array): void {
      map.set(keyid, pub);
    },
  };
}
