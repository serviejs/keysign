import { pbkdf2Sync, createHmac, timingSafeEqual } from 'crypto'

/**
 * Algorithm configuration.
 */
export interface Algorithm {
  hmacKeySize: number
  hmacAlgorithm: string
  hmacDigestSize: number
}

/**
 * Supported algorithms - using numeric index allows for 256 (1 byte) different
 * algorithms with backward compatibility until a breaking change is required.
 */
export const ALGORITHMS: Algorithm[] = [
  {
    hmacKeySize: 32,
    hmacAlgorithm: 'sha256',
    hmacDigestSize: 32
  }
]

/**
 * Allow key generation to be configured (not highly recommended).
 */
export interface KeyOptions {
  salt: string
  iterations: number
  algorithm: string
}

/**
 * Default key generation configuration - keys should already be secure.
 */
export const DEFAULT_KEY_OPTIONS = {
  salt: 'Keysign',
  iterations: 100,
  algorithm: 'sha256'
}

/**
 * Supports a generic interface for iteroperability with other libraries.
 */
export class Keysign {

  keys: Array<Buffer>
  tag: Buffer
  algorithm: number

  constructor (keys: Buffer[], options: KeyOptions = DEFAULT_KEY_OPTIONS, algorithm = 0) {
    if (!(algorithm in ALGORITHMS)) {
      throw new TypeError(`Unknown algorithm: ${Number(algorithm)}`)
    }

    this.tag = Buffer.alloc(1, algorithm)
    this.algorithm = algorithm

    this.keys = keys.map((key) => {
      const { hmacKeySize } = ALGORITHMS[this.algorithm]

      return pbkdf2Sync(key, options.salt, options.iterations, hmacKeySize, 'sha512')
    })
  }

  encode (data: Buffer) {
    const key = this.keys[0]
    const { hmacAlgorithm, hmacDigestSize } = ALGORITHMS[this.algorithm]

    const mac = createHmac(hmacAlgorithm, key).update(data).digest()
    const totalLength = 1 + hmacDigestSize + data.length

    return Buffer.concat([this.tag, mac, data], totalLength)
  }

  decode (data: Buffer): Buffer | undefined {
    if (!data.length) return undefined

    const index = data.readUInt8(0)
    const algorithm = ALGORITHMS[index]

    // Unknown algorithm input.
    if (!(index in ALGORITHMS)) return undefined

    // Iterate over each key and check.
    for (const key of this.keys) {
      const message = this._read(data, key, algorithm)
      if (message) return message
    }
  }

  private _read (data: Buffer, key: Buffer, algorithm: Algorithm) {
    const { hmacAlgorithm, hmacDigestSize } = algorithm

    if (data.length < (1 + hmacDigestSize)) return undefined

    const mac = data.slice(1, 1 + hmacDigestSize)
    const value = data.slice(1 + hmacDigestSize)

    const dataMac = createHmac(hmacAlgorithm, key).update(value).digest()

    if (!timingSafeEqual(mac, dataMac)) return undefined

    return value
  }

}
