#!/usr/bin/env node
'use strict';

/*
 * Focused, no-dependency checks for the path-search reveal flow in web/app.js.
 *
 * Runs the real app.js against a tiny DOM stub and a stub fetch that records
 * request order. Verifies:
 *   1. a result click fetches the ancestor chain once, then expands each
 *      branch sequentially (children of 1, then of 2, then the node), and
 *      selects, focuses and scrolls to the target;
 *   2. a truncated parent still gets the known chain child inserted;
 *   3. a second quick click supersedes the first (token guard);
 *   4. direct tree clicks still behave as before.
 *
 *   node tests/reveal.test.cjs
 */

const fs = require('fs');
const path = require('path');

const APP_PATH = path.join(__dirname, '..', 'web', 'app.js');
const APP_SOURCE = fs.readFileSync(APP_PATH, 'utf8');

// -- minimal DOM ------------------------------------------------------------

class TextNode {
  constructor(text) { this.nodeType = 3; this.text = String(text); this.parentNode = null; }
  get textContent() { return this.text; }
  set textContent(v) { this.text = String(v); }
}

class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.dataset = {};
    this.attributes = {};
    this.style = {};
    this.hidden = false;
    this.value = '';
    this._text = '';
    this._class = '';
    this.listeners = {};
    this.focused = false;
    this.scrolled = null;
    const self = this;
    this.classList = {
      contains: function (c) { return self._class.split(/\s+/).indexOf(c) !== -1; },
      add: function (c) { if (!this.contains(c)) self._class = (self._class + ' ' + c).trim(); },
      remove: function (c) {
        self._class = self._class.split(/\s+/).filter(function (x) { return x && x !== c; }).join(' ');
      }
    };
  }
  get className() { return this._class; }
  set className(v) { this._class = String(v); }
  get firstChild() { return this.children[0] || null; }
  get textContent() {
    return this.children.map(function (c) { return c.textContent; }).join('') + this._text;
  }
  set textContent(v) { this._text = v === null || v === undefined ? '' : String(v); this.children = []; }
  appendChild(c) {
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this;
    this.children.push(c);
    return c;
  }
  removeChild(c) {
    const i = this.children.indexOf(c);
    if (i >= 0) this.children.splice(i, 1);
    c.parentNode = null;
    return c;
  }
  insertBefore(c, ref) {
    if (ref === null || ref === undefined) return this.appendChild(c);
    const i = this.children.indexOf(ref);
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this;
    this.children.splice(i < 0 ? this.children.length : i, 0, c);
    return c;
  }
  setAttribute(k, v) { this.attributes[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, extra) {
    const ev = Object.assign({ preventDefault: function () {}, stopPropagation: function () {}, target: this }, extra);
    (this.listeners[type] || []).slice().forEach(function (fn) { fn(ev); });
  }
  focus() { this.focused = true; this.ownerDocument.activeElement = this; }
  scrollIntoView(opts) { this.scrolled = opts; }
  querySelector(sel) { return descendants(this).filter(function (n) { return matches(n, sel); })[0] || null; }
  querySelectorAll(sel) { return descendants(this).filter(function (n) { return matches(n, sel); }); }
  closest(sel) {
    let n = this;
    while (n) { if (matches(n, sel)) return n; n = n.parentNode; }
    return null;
  }
}

function descendants(root) {
  const out = [];
  (function walk(n) {
    n.children.forEach(function (c) {
      if (c instanceof El) { out.push(c); walk(c); }
    });
  })(root);
  return out;
}

function matches(el, sel) {
  const m = /^([a-zA-Z]*)((?:.[\w-]+)*)$/.exec(sel);
  if (!m) throw new Error('unsupported selector: ' + sel);
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  const classes = m[2] ? m[2].slice(1).split('.') : [];
  return classes.every(function (c) { return el.classList.contains(c); });
}

function buildDom() {
  const doc = {
    readyState: 'complete',
    activeElement: null,
    listeners: {},
    createElement: function (tag) { const e = new El(tag); e.ownerDocument = doc; return e; },
    createTextNode: function (t) { return new TextNode(t); },
    addEventListener: function (t, fn) { (doc.listeners[t] = doc.listeners[t] || []).push(fn); }
  };
  const root = doc.createElement('div');
  doc.body = root;

  const ids = {};
  function add(tag, id, parent) {
    const e = doc.createElement(tag);
    if (id) { e.setAttribute('id', id); ids[id] = e; }
    (parent || root).appendChild(e);
    return e;
  }

  add('p', 'status-bar');
  const explore = add('section', 'panel-explore');
  add('form', 'path-search-form', explore);
  add('input', 'path-search-input', explore);
  add('div', 'path-search-results', explore);
  add('div', 'tree', explore);
  add('button', 'tree-refresh', explore);
  const principals = add('section', 'panel-principals');
  add('form', 'principal-search-form', principals);
  add('input', 'principal-search-input', principals);
  add('div', 'principal-search-results', principals);
  add('div', 'principal-detail', principals);
  add('div', 'detail-pane');

  // Collapse the wrapper so querySelector on the body finds every id.
  doc.getElementById = function (id) { return ids[id] || null; };
  doc.querySelectorAll = function (sel) { return descendants(root).filter(function (n) { return matches(n, sel); }); };
  doc.ids = ids;
  return doc;
}

// -- stub fetch -------------------------------------------------------------

function node(id, name, parentId, hasChildren) {
  return {
    id: id, parent_id: parentId, path: name, name: name.split('/').pop() || name,
    depth: 0, has_children: hasChildren
  };
}

function makeFetch(routes, log, delays) {
  return function (url) {
    const u = new URL(url);
    const key = u.pathname + (u.search || '');
    log.push(key);
    const ms = delays ? delays(u) : 0;
    const body = routes(u);
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (body === undefined) {
          resolve({ ok: false, status: 404, statusText: 'Not Found', text: function () { return Promise.resolve('{}'); } });
        } else {
          resolve({ ok: true, status: 200, statusText: 'OK', text: function () { return Promise.resolve(JSON.stringify(body)); } });
        }
      }, ms);
    });
  };
}

function boot(doc, fetchStub) {
  const win = { location: { origin: 'http://localhost' }, addEventListener: function () {} };
  const run = new Function('document', 'window', 'fetch', 'URL', APP_SOURCE);
  run(doc, win, fetchStub, URL);
}

const tick = function (n) {
  let p = Promise.resolve();
  for (let i = 0; i < (n || 8); i++) p = p.then(function () { return new Promise(function (r) { setTimeout(r, 0); }); });
  return p;
};
const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

function assert(cond, msg) { if (!cond) throw new Error('FAIL: ' + msg); }

function resultButtons(doc) {
  return doc.ids['path-search-results'].querySelectorAll('.link-button');
}

function submitPathSearch(doc, q) {
  doc.ids['path-search-input'].value = q;
  doc.ids['path-search-form'].dispatch('submit');
}

function buttonFor(doc, id) {
  const all = doc.ids.tree.querySelectorAll('.node-select');
  for (let i = 0; i < all.length; i++) {
    if (all[i].dataset.nodeId === String(id)) return all[i];
  }
  return null;
}

// -- scenarios --------------------------------------------------------------

const TREE = {
  '': [node(1, '/data', null, true)],
  '1': [node(2, '/data/team', 1, true)],
  '2': [node(3, '/data/team/docs', 2, false)]
};

function childrenRoute(overrides) {
  return function (u) {
    const parent = u.searchParams.get('parent_id');
    const key = parent === null ? '' : parent;
    if (overrides && Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    return { parent_id: parent === null ? null : Number(parent), children: TREE[key] || [], truncated: false };
  };
}

async function scenarioSequential() {
  const doc = buildDom();
  const log = [];
  const routes = function (u) {
    if (u.pathname === '/api/status') return { node_count: 3 };
    if (u.pathname === '/api/search/paths') return { results: [{ id: 3, path: '/data/team/docs', name: 'docs' }] };
    if (u.pathname === '/api/ancestors') return { ancestors: [node(1, '/data', null, true), node(2, '/data/team', 1, true), node(3, '/data/team/docs', 2, false)] };
    if (u.pathname === '/api/node') return { node: node(Number(u.searchParams.get('id')), '/data/team/docs', 2, false), aces: [], scan_errors: [] };
    if (u.pathname === '/api/children') return childrenRoute()(u);
    return undefined;
  };
  boot(doc, makeFetch(routes, log, null));
  await tick();

  assert(buttonFor(doc, 1), 'roots should be loaded on startup');
  const rootsFetches = log.filter(function (k) { return k.indexOf('/api/children') === 0; }).length;

  submitPathSearch(doc, 'docs');
  await tick();
  const buttons = resultButtons(doc);
  assert(buttons.length === 1, 'path search should render one result button');

  buttons[0].dispatch('click');
  await tick(20);

  const order = log.filter(function (k) {
    return k.indexOf('/api/ancestors') === 0 || k.indexOf('/api/children?parent_id') === 0 || k.indexOf('/api/node') === 0;
  });
  assert(order[0] === '/api/ancestors?id=3', 'chains fetched once first, got ' + order[0]);
  assert(order[1] === '/api/children?parent_id=1', 'then expand parent 1, got ' + order[1]);
  assert(order[2] === '/api/children?parent_id=2', 'then expand parent 2, got ' + order[2]);
  assert(order[3] === '/api/node?id=3', 'then load target detail, got ' + order[3]);
  assert(order.length === 4, 'exactly one chain pass, got ' + order.join(', '));
  assert(log.filter(function (k) { return k.indexOf('/api/children') === 0; }).length === rootsFetches + 2,
    'roots are reused, not reloaded');

  const target = buttonFor(doc, 3);
  assert(target, 'target should be in the tree after reveal');
  assert(target.getAttribute('aria-current') === 'true', 'target should be aria-current');
  assert(target.focused, 'target button should be focused');
  assert(target.scrolled && target.scrolled.block === 'center', 'target should be scrolled into view');
  const toggle2 = buttonFor(doc, 2).closest('li.tree-item').querySelector('button.tree-toggle');
  assert(toggle2.getAttribute('aria-expanded') === 'true', 'ancestor row should be expanded');
  assert(!doc.ids['path-search-results'].querySelector('.reveal-status'), 'loading state cleared on success');

  // Direct tree click keeps the old behaviour: select, no reveal.
  const before = log.length;
  buttonFor(doc, 2).dispatch('click');
  await tick();
  const direct = log.slice(before);
  assert(direct.length === 1 && direct[0] === '/api/node?id=2', 'direct click only loads detail, got ' + direct.join(', '));
  assert(buttonFor(doc, 2).getAttribute('aria-current') === 'true', 'direct click selects the node');
  console.log('scenario: sequential expansion OK');
}

async function scenarioTruncated() {
  const doc = buildDom();
  const log = [];
  const routes = function (u) {
    if (u.pathname === '/api/status') return { node_count: 3 };
    if (u.pathname === '/api/search/paths') return { results: [{ id: 3, path: '/data/team/docs' }] };
    if (u.pathname === '/api/ancestors') return { ancestors: [node(1, '/data', null, true), node(2, '/data/team', 1, true), node(3, '/data/team/docs', 2, false)] };
    if (u.pathname === '/api/node') return { node: node(3, '/data/team/docs', 2, false), aces: [], scan_errors: [] };
    if (u.pathname === '/api/children') {
      const parent = u.searchParams.get('parent_id');
      if (parent === null) return { parent_id: null, children: [], truncated: true };       // root list truncated
      if (parent === '1') return { parent_id: 1, children: [node(2, '/data/team', 1, true)], truncated: false };
      if (parent === '2') return { parent_id: 2, children: [], truncated: true };            // child omitted
      return { parent_id: Number(parent), children: [], truncated: false };
    }
    return undefined;
  };
  boot(doc, makeFetch(routes, log, null));
  await tick();

  assert(!buttonFor(doc, 1), 'precondition: truncated root list omits the root');
  submitPathSearch(doc, 'docs');
  await tick();
  resultButtons(doc)[0].dispatch('click');
  await tick(20);

  assert(buttonFor(doc, 1), 'missing chain root should be inserted');
  assert(buttonFor(doc, 2), 'known chain child should be inserted when truncated');
  const target = buttonFor(doc, 3);
  assert(target && target.getAttribute('aria-current') === 'true', 'target revealed despite truncation');
  assert(log.indexOf('/api/node?id=3') !== -1, 'target detail loaded');
  console.log('scenario: truncated children insertion OK');
}

async function scenarioRace() {
  const doc = buildDom();
  const log = [];
  const routes = function (u) {
    if (u.pathname === '/api/status') return { node_count: 6 };
    if (u.pathname === '/api/search/paths') {
      return { results: [{ id: 3, path: '/data/team/docs' }, { id: 6, path: '/data/other/notes' }] };
    }
    if (u.pathname === '/api/ancestors') {
      const id = u.searchParams.get('id');
      if (id === '3') return { ancestors: [node(1, '/data', null, true), node(2, '/data/team', 1, true), node(3, '/data/team/docs', 2, false)] };
      return { ancestors: [node(1, '/data', null, true), node(5, '/data/other', 1, true), node(6, '/data/other/notes', 5, false)] };
    }
    if (u.pathname === '/api/node') return { node: node(Number(u.searchParams.get('id')), '/x', 1, false), aces: [], scan_errors: [] };
    if (u.pathname === '/api/children') {
      const parent = u.searchParams.get('parent_id');
      if (parent === null) return { children: [node(2, '/data/team', 1, true), node(5, '/data/other', 1, true)] };
      if (parent === '1') return { children: [node(2, '/data/team', 1, true), node(5, '/data/other', 1, true)] };
      if (parent === '2') return { children: [node(3, '/data/team/docs', 2, false)] };
      if (parent === '5') return { children: [node(6, '/data/other/notes', 5, false)] };
      return { children: [] };
    }
    return undefined;
  };
  const delays = function (u) {
    return (u.pathname === '/api/ancestors' && u.searchParams.get('id') === '3') ? 40 : 0;
  };
  boot(doc, makeFetch(routes, log, delays));
  await tick();

  submitPathSearch(doc, 'data');
  await tick();
  const buttons = resultButtons(doc);
  assert(buttons.length === 2, 'two results expected');
  buttons[0].dispatch('click');   // slow chain for id 3
  buttons[1].dispatch('click');   // supersedes it
  await sleep(120);
  await tick(20);

  assert(log.indexOf('/api/node?id=3') === -1, 'superseded click must not select node 3');
  assert(log.indexOf('/api/node?id=6') !== -1, 'latest click selects node 6');
  const target = buttonFor(doc, 6);
  assert(target && target.getAttribute('aria-current') === 'true', 'node 6 is selected and current');
  assert(target.focused, 'node 6 focused');
  console.log('scenario: rapid-click race OK');
}

async function main() {
  await scenarioSequential();
  await scenarioTruncated();
  await scenarioRace();
  console.log('reveal tests OK');
}

main().catch(function (err) {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
