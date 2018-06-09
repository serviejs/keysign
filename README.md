# Keysign

[![NPM version](https://img.shields.io/npm/v/keysign.svg?style=flat)](https://npmjs.org/package/keysign)
[![NPM downloads](https://img.shields.io/npm/dm/keysign.svg?style=flat)](https://npmjs.org/package/keysign)
[![Build status](https://img.shields.io/travis/serviejs/keysign.svg?style=flat)](https://travis-ci.org/serviejs/keysign)
[![Test coverage](https://img.shields.io/coveralls/serviejs/keysign.svg?style=flat)](https://coveralls.io/r/serviejs/keysign?branch=master)

> Data signing and verification for rotating credentials and algorithms.

_(Inspired by [keygrip](https://github.com/crypto-utils/keygrip) and API compatible with [keycrypt](https://github.com/serviejs/keycrypt))._

## Installation

```
npm install keysign --save
```

## Usage

Signs a `Buffer` using the first `key` (secret) and returns the data. Upon decoding, checks each secret for a valid HMAC and returns the plain data (or `undefined` if nothing matches).

```ts
import { Keysign } from 'keysign'

const secrets = [Buffer.from('secret', 'utf8')]
const keysign = new Keysign(secrets)

const raw = Buffer.from('some data', 'utf8')
const signed = keysign.encode(raw)
const verified = keysign.decode(encrypted)

assert.equal(verified, raw)
```

## TypeScript

This project is using [TypeScript](https://github.com/Microsoft/TypeScript) and publishes the definitions to NPM.

## License

Apache 2.0
