import { Keysign } from './index'

describe('keysign', () => {
  const secrets = [Buffer.from('secret', 'utf8'), Buffer.from('fallback', 'utf8')]
  const keysign = new Keysign(secrets)

  it('should throw when selecting an unknown algorithm', () => {
    expect(() => new Keysign([], undefined, -1)).toThrowError('Unknown algorithm: -1')
  })

  it('should sign and verify data', () => {
    const raw = Buffer.from('example', 'utf8')
    const encrypted = keysign.encode(raw)
    const decrypted = keysign.decode(encrypted)

    expect(decrypted).toEqual(raw)
  })

  it('should fail to decrypt when data is small', () => {
    const result = keysign.decode(Buffer.alloc(10))

    expect(result).toEqual(undefined)
  })

  it('should fail to decode empty buffer', () => {
    const result = keysign.decode(Buffer.alloc(0))

    expect(result).toEqual(undefined)
  })

  it('should verify the hmac is correct', () => {
    const signed = keysign.encode(Buffer.from('example', 'utf8'))

    // Mess with HMAC.
    signed.set([1, 2, 3], 1)

    const verified = keysign.decode(signed)

    expect(verified).toBe(undefined)
  })

  it('should fail to decode if algorithm byte is unknown', () => {
    const signed = keysign.encode(Buffer.from('example', 'utf8'))

    // Change algorithm.
    signed.set([55], 0)

    const verified = keysign.decode(signed)

    expect(verified).toBe(undefined)
  })

  it('should verify with old secret', () => {
    const raw = Buffer.from('super secret message', 'utf8')
    const signed = new Keysign([secrets[1]]).encode(raw)
    const verified = keysign.decode(signed)

    expect(verified).toEqual(raw)
  })
})
