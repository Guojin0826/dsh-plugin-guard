// Final smoke: the REBUILT bundle still renders the settings panel.
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import vm from 'node:vm'

const require = createRequire(import.meta.url)
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')

const code = readFileSync('E:/AI/CJ/dsh-plugin-guard/lib/client.js', 'utf8')
const factories = new Map()
const stripClientSuffix = (s) => s.endsWith('/client') ? s.slice(0, -7) : s

const sandbox = {
  window: { __ModuleLoader__: { load(r) { factories.set(stripClientSuffix(r.id), r.factory) } } },
  document: {
    createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, classList: { contains: () => false } }),
    head: { appendChild() {} },
    body: { getAttribute: () => null, appendChild() {} },
    documentElement: { getAttribute: () => null },
    querySelector: () => null,
    addEventListener() {}, removeEventListener() {},
  },
  navigator: { userAgent: 'node' },
  console, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  MutationObserver: class { observe() {} disconnect() {} },
  fetch: () => Promise.reject(new Error('no network in test')),
  location: { href: 'http://127.0.0.1:3080/' },
}
sandbox.globalThis = sandbox
vm.createContext(sandbox)
vm.runInContext(code, sandbox, { filename: 'client.js' })

console.log('bundle registers:', JSON.stringify([...factories.keys()]))
const id = [...factories.keys()][0]
const factory = factories.get(id)

const requireShim = (spec) => {
  if (spec === 'react') return React
  if (spec === 'react/jsx-runtime') return require('react/jsx-runtime')
  if (spec === 'react-dom') return require('react-dom')
  throw new Error('external not provided: ' + spec)
}

const exports_ = factory(requireShim)
console.log('client exports  :', Object.keys(exports_).sort().join(', '))
console.log('inject          :', JSON.stringify(exports_.inject))

// drive apply() with a stub ctx and capture the settings.section registration
let reg = null
const t = (k) => `[${k}]`
const ctx = {
  effect(fn, label) { try { const d = fn(); return typeof d === 'function' ? d : () => {} } catch (e) { console.log('  effect threw:', e.message); return () => {} } },
  locale: { register() {}, bind: () => t, get: () => 'zh' },
  reflect: { get: () => ({}) },
  remote: { $mount: async () => () => {} },
  slots: {
    inject(name, fn) { if (name === 'settings.section') fn() },
    register(options, Component) { reg = { options, Component } ; return () => {} },
  },
}
try {
  exports_.apply(ctx)
  console.log('apply()         : OK')
} catch (e) {
  console.log('apply() THREW   :', e.message)
}

if (reg === null) { console.log('NO settings.section registration!'); process.exit(1) }
console.log('slot            :', `name=${reg.options.name} id=${reg.options.id} order=${reg.options.order}`)
const injected = reg.options.inject()
const keys = Object.keys(injected)
console.log('injected keys   :', keys.length)
const callable = keys.filter((k) => typeof injected[k] === 'function')
console.log('callable        :', callable.length, '/', keys.length)

// render
const Comp = reg.Component
const props = { ...injected, t, locale: 'zh', __: t }
for (const k of keys) if (typeof injected[k] !== 'function') props[k] = injected[k]
try {
  const html = renderToStaticMarkup(React.createElement(Comp, props))
  console.log('')
  console.log('RENDER OK, html length =', html.length)
  console.log('first 220 chars:', html.slice(0, 220))
} catch (e) {
  console.log('')
  console.log('RENDER THREW:', e.message)
  console.log(e.stack?.split('\n').slice(0, 6).join('\n'))
}
