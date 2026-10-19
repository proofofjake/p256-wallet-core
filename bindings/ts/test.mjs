// Checks the WebAssembly binding is wired up. The logic itself is tested in Rust (`cargo test`).
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import * as core from './pkg/p256_wallet_core.js'

core.initSync({ module: readFileSync(new URL('./pkg/p256_wallet_core_bg.wasm', import.meta.url)) })

test('calls into the core', () => {
  assert.equal(core.coreVersion(), '0.3.0')
  assert.equal(core.factoryAddress(), '0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a')
  assert.equal(core.parseUnits('1.5', 6), '0x16e360')
  const owners = ['11', '22'].map((b) => `0x${b.repeat(64)}`)
  assert.equal(core.accountAddress(owners), '0x2c12B943Dc11D552Fa5648796BD0e85Ac4ddE92b')
  assert.equal(core.chains()[0].knownTokens[0].symbol, 'USDC')
})

test('errors carry readable messages', () => {
  assert.throws(() => core.checksumAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'), {
    message: "Address checksum doesn't match (check for a typo): 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
  })
  assert.throws(() => core.ownerBytes({ x: '0x01' }), /Invalid public key/)
  assert.throws(() => core.checksumAddress('nope'), { name: 'Error', kind: 'invalidInput' })
})

test('refusals have their own kind', () => {
  const owners = [`0x${'11'.repeat(64)}`]
  const account = core.accountAddress(owners)
  const takeover = core.encodeFunctionCall('upgradeToAndCall(address,bytes)', [account, '0x'])
  const op = core.buildUserOperation(account, '0x0', true, owners, [{ target: account, value: '0x0', data: takeover.data }], { maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x1' }, 0)
  assert.throws(() => core.reviewUserOperation(op, 84532, [], [], undefined), (error) => {
    assert.ok(error instanceof Error)
    assert.equal(error.kind, 'refused')
    assert.match(error.message, /^This wallet won't sign this/)
    return true
  })
})

test('records round-trip as camelCase objects', () => {
  const call = core.transferCall(undefined, '0x000000000000000000000000000000000000dEaD', '0x1')
  assert.deepEqual(call, { target: '0x000000000000000000000000000000000000dEaD', value: '0x1', data: '0x' })
})
