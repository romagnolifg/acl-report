'use strict';

/*
 * ACL Report frontend.
 * Server data is rendered only through DOM nodes and textContent; nothing
 * that arrives from the API is ever parsed as HTML.
 */
(function () {
  var API = {
    status: '/api/status',
    children: '/api/children',
    node: '/api/node',
    ancestors: '/api/ancestors',
    searchPaths: '/api/search/paths',
    searchPrincipals: '/api/search/principals',
    principal: '/api/principal'
  };
  var SEARCH_LIMIT = 50;
  var PRINCIPAL_PAGE = 100;

  var EXCLUDED_NODE_KEYS = {
    aces: 1, entries: 1, acl: 1, scan_errors: 1, errors: 1,
    children: 1, subfolders: 1, parent_id: 1
  };

  var ERROR_KEYS = ['error_message', 'message', 'error', 'detail', 'msg'];
  var UNRESOLVED_KEYS = ['unresolved', 'is_unresolved', 'isUnresolved'];

  function errorMessage(o) {
    if (!o || typeof o !== 'object') return '';
    var err = o.error;
    if (err && typeof err === 'object') {
      var nested = pick(err, ['error_message', 'message']);
      if (nested !== undefined && typeof nested !== 'object') return asText(nested);
    }
    var v = pick(o, ERROR_KEYS);
    return (v === undefined || typeof v === 'object') ? '' : asText(v);
  }

  // Body text for a failed response: prefer the server's structured error
  // message over the raw JSON body.
  function errorDetail(body) {
    var parsed;
    try { parsed = JSON.parse(body); } catch (e) { parsed = undefined; }
    var msg = '';
    if (typeof parsed === 'string') msg = parsed;
    else if (parsed && typeof parsed === 'object') msg = errorMessage(parsed);
    return msg || (body ? String(body).slice(0, 200) : '');
  }

  function $(id) { return document.getElementById(id); }

  function fetchJSON(path, params) {
    var url = new URL(path, window.location.origin);
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    });
    return fetch(url.toString(), { headers: { Accept: 'application/json' } }).then(function (res) {
      if (!res.ok) {
        return res.text().then(function (body) {
          var detail = errorDetail(body);
          throw new Error('HTTP ' + res.status + ' ' + res.statusText + (detail ? ' - ' + detail : ''));
        }, function () {
          throw new Error('HTTP ' + res.status + ' ' + res.statusText);
        });
      }
      return res.text().then(function (body) {
        try { return JSON.parse(body); }
        catch (e) { throw new Error('Response was not valid JSON'); }
      });
    }, function (err) {
      throw new Error('Network request failed (' + (err && err.message ? err.message : 'unknown error') + ')');
    });
  }

  function pick(obj, names) {
    if (!obj || typeof obj !== 'object') return undefined;
    for (var i = 0; i < names.length; i++) {
      var v = obj[names[i]];
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return undefined;
  }

  function firstDefined(objs, names) {
    for (var i = 0; i < objs.length; i++) {
      var o = objs[i];
      if (!o || typeof o !== 'object') continue;
      for (var j = 0; j < names.length; j++) {
        var v = o[names[j]];
        if (v !== undefined && v !== null) return v;
      }
    }
    return undefined;
  }

  function arr(v) {
    if (v === undefined || v === null) return [];
    return Array.isArray(v) ? v : [v];
  }

  function asText(v) {
    if (v === undefined || v === null) return '';
    if (typeof v === 'object') {
      if (Object.prototype.toString.call(v) === '[object Date]') return v.toISOString();
      try { return JSON.stringify(v); } catch (e) { return String(v); }
    }
    return String(v);
  }

  function el(tag, opts, children) {
    var node = document.createElement(tag);
    if (opts) {
      Object.keys(opts).forEach(function (k) {
        var v = opts[k];
        if (v === undefined || v === null) return;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = v;
        else if (k === 'attrs') {
          Object.keys(v).forEach(function (a) {
            if (v[a] !== undefined && v[a] !== null) node.setAttribute(a, String(v[a]));
          });
        } else if (k === 'data') {
          Object.keys(v).forEach(function (d) {
            if (v[d] !== undefined && v[d] !== null) node.dataset[d] = String(v[d]);
          });
        } else if (k === 'style') {
          Object.keys(v).forEach(function (s) { node.style[s] = v[s]; });
        } else if (k.indexOf('on') === 0) {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else {
          node[k] = v;
        }
      });
    }
    var kids = Array.isArray(children) ? children : (children === undefined || children === null ? [] : [children]);
    kids.forEach(function (c) {
      if (c === undefined || c === null || c === false) return;
      if (typeof c === 'string' || typeof c === 'number') node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    });
    return node;
  }

  function badge(label, kind, title) {
    return el('span', {
      class: 'badge badge-' + kind,
      text: label,
      attrs: title ? { title: title } : null
    });
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function loadingInto(container, msg) {
    clear(container);
    container.appendChild(el('p', { class: 'state state-loading', attrs: { role: 'status' }, text: msg || 'Loading...' }));
  }

  function errorInto(container, msg, retry) {
    clear(container);
    container.appendChild(el('div', { class: 'state state-error', attrs: { role: 'alert' } }, [
      el('p', { text: msg }),
      retry ? el('button', { class: 'button', type: 'button', text: 'Retry', onclick: retry }) : null
    ]));
  }

  function nodeId(n) {
    if (n === undefined || n === null) return undefined;
    if (typeof n === 'object') return pick(n, ['id', 'node_id', 'nodeId', 'nid']);
    return n;
  }

  function nodeName(n) {
    if (!n || typeof n !== 'object') return '';
    return asText(pick(n, ['name', 'label', 'title', 'path', 'full_path']));
  }

  function nodeHasChildren(n) {
    if (!n || typeof n !== 'object') return undefined;
    var h = pick(n, ['has_children', 'hasChildren', 'is_dir', 'is_directory', 'child_count', 'children_count']);
    if (typeof h === 'boolean') return h;
    if (typeof h === 'number') return h > 0;
    if (Array.isArray(n.children)) return n.children.length > 0;
    return undefined;
  }

  function aceEffect(a) {
    var t = pick(a, ['effect', 'access_type', 'type', 'ace_type', 'entry_type', 'allow_deny', 'permission_type']);
    if (typeof t === 'string') {
      var s = t.toLowerCase();
      if (s.indexOf('deny') !== -1) return 'deny';
      if (s.indexOf('allow') !== -1 || s.indexOf('permit') !== -1) return 'allow';
    }
    if (typeof t === 'boolean') return t ? 'allow' : 'deny';
    var d = pick(a, ['deny', 'is_deny', 'isDeny']);
    if (typeof d === 'boolean') return d ? 'deny' : 'allow';
    return 'unknown';
  }

  function aceSource(a) {
    var inh = pick(a, ['inherited', 'is_inherited', 'isInherited']);
    if (typeof inh === 'boolean') return inh ? 'inherited' : 'explicit';
    var src = pick(a, ['source', 'origin', 'scope', 'entry_source', 'inheritance']);
    if (typeof src === 'string') {
      var s = src.toLowerCase();
      if (s.indexOf('inherit') !== -1) return 'inherited';
      if (s.indexOf('explicit') !== -1 || s.indexOf('direct') !== -1) return 'explicit';
    }
    return 'unknown';
  }

  function aceRights(a) {
    var r = pick(a, ['rights', 'permissions', 'perms', 'right', 'mask', 'effective_rights']);
    if (r === undefined) return [];
    if (Array.isArray(r)) return r.map(asText);
    if (typeof r === 'object') return Object.keys(r).filter(function (k) { return r[k]; });
    // Real scanner data delimits rights with semicolons ("read;write").
    return String(r).split(/[;,]+/).map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
  }

  // Scanner right identifiers mapped to concise labels. Anything not listed
  // falls back to underscore-free title text, so no right is ever dropped.
  var RIGHT_LABELS = {
    list_folder_or_read_data: 'List folder / read',
    create_file_or_write_data: 'Create / write',
    read_extended_attributes: 'Read extended attributes',
    traverse_folder_or_execute_file: 'Traverse / execute',
    full_control_marker: 'Full control'
  };

  function rightLabel(v) {
    var s = asText(v).trim();
    if (!s) return '';
    var known = RIGHT_LABELS[s.toLowerCase()];
    if (known) return known;
    var words = s.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
    if (!words) return s;
    return words.charAt(0).toUpperCase() + words.slice(1);
  }

  function rightItems(labels, itemClass) {
    return labels.map(function (label) {
      return el('li', { class: itemClass }, [
        el('span', { class: 'rights-check', attrs: { 'aria-hidden': 'true' }, text: '\u2713' }),
        el('span', { text: label })
      ]);
    });
  }

  // One compact view of a parsed rights list: chips when short, a collapsed
  // native disclosure when long. "Unspecified" stays plain text.
  function rightsView(rawRights) {
    var labels = arr(rawRights).map(rightLabel).filter(function (s) { return s !== ''; });
    if (!labels.length) return el('span', { class: 'rights-unspecified', text: 'Unspecified' });
    if (labels.length <= 4) {
      return el('ul', { class: 'rights-chips' }, rightItems(labels, 'rights-chip'));
    }
    var full = labels.indexOf('Full control') !== -1;
    return el('details', { class: 'rights-details' }, [
      el('summary', {
        class: 'rights-summary',
        text: (full ? 'Full control \u00B7 ' : '') + labels.length + ' permissions'
      }),
      el('ul', { class: 'rights-checklist' }, rightItems(labels, 'rights-item'))
    ]);
  }

  function rightsCell(ace) {
    return el('td', { class: 'cell-rights' }, [rightsView(aceRights(ace))]);
  }

  function acePrincipal(a) {
    return pick(a, ['principal', 'principal_name', 'principal_key', 'trustee', 'identity', 'who', 'account', 'sid', 'name']);
  }

  // A raw identifier that carries no resolved account name.
  function unresolvedText(v) {
    var s = String(v).trim();
    if (s === '') return true;
    if (s.toLowerCase().indexOf('unresolved') !== -1) return true;
    return /^[Ss]-[0-9]/.test(s);
  }

  // Truthiness of the scanner's unresolved marker: 0/1, "0"/"1", false/true,
  // yes/no, empty string.
  function flagIsTrue(v) {
    if (v === true) return true;
    if (typeof v === 'number') return v !== 0;
    if (typeof v === 'string') {
      var s = v.trim().toLowerCase();
      return s !== '' && s !== '0' && s !== 'false' && s !== 'no' && s !== 'off';
    }
    return false;
  }

  // The scanner's own unresolved field when it states one. undefined means it
  // said nothing, so the caller falls back to the name heuristics.
  function statedUnresolved(objs) {
    for (var i = 0; i < objs.length; i++) {
      var o = objs[i];
      if (!o || typeof o !== 'object') continue;
      for (var j = 0; j < UNRESOLVED_KEYS.length; j++) {
        if (Object.prototype.hasOwnProperty.call(o, UNRESOLVED_KEYS[j])) {
          return flagIsTrue(o[UNRESOLVED_KEYS[j]]);
        }
      }
    }
    return undefined;
  }

  function isUnresolved(a) {
    if (a === undefined || a === null) return true;
    if (typeof a === 'object') {
      var flag = statedUnresolved([a, a.principal, a.principal_ref, a.trustee]);
      if (flag !== undefined) return flag;
      var v = pick(a, ['principal_name', 'principal', 'principal_key', 'trustee', 'identity', 'who', 'account', 'sid', 'name']);
      return v === undefined ? true : unresolvedText(asText(v));
    }
    if (typeof a === 'number') return a !== 0;
    if (typeof a === 'boolean') return a;
    return unresolvedText(a);
  }

  function inheritanceDisabled(n) {
    if (!n || typeof n !== 'object') return false;
    // inherit_parent === 0 means inheritance is switched off. null/undefined
    // means the scan did not state it, which is unknown, not disabled.
    var ip = n.inherit_parent;
    if (ip === 0 || ip === '0' || ip === false) return true;
    var d = pick(n, ['inheritance_disabled', 'inherit_disabled', 'inheritance_blocked', 'no_inherit', 'inherit_none', 'protected', 'is_protected']);
    if (typeof d === 'boolean') return d;
    var s = pick(n, ['inheritance', 'inherit', 'inheritance_state']);
    if (typeof s === 'string') {
      var t = s.toLowerCase();
      if (t.indexOf('disab') !== -1 || t.indexOf('block') !== -1 || t === 'none' || t === 'off') return true;
    }
    return false;
  }

  function effectBadge(effect) {
    if (effect === 'deny') return badge('Deny', 'danger', 'This entry denies access');
    if (effect === 'allow') return badge('Allow', 'ok', 'This entry grants access');
    return badge('Unknown', 'info', 'The effect of this entry was not stated');
  }

  function sourceBadge(source) {
    if (source === 'inherited') return badge('Inherited', 'muted', 'Inherited from a parent object');
    if (source === 'explicit') return badge('Explicit', 'info', 'Set directly on this object');
    return badge('Unknown', 'info', 'The source of this entry was not stated');
  }

  // Takes the raw ACE so the scanner's own unresolved marker is honoured; the
  // displayed name still prefers principal_name.
  function principalCell(ace) {
    var value = acePrincipal(ace);
    var unresolved = isUnresolved(ace);
    return el('td', { class: 'cell-principal' }, [
      el('span', { class: 'principal-name', text: unresolved ? (asText(value) || '(unresolved)') : asText(value) }),
      unresolved
        ? badge('Unresolved', 'warn', 'No account name was resolved for this entry; the raw identifier is shown')
        : null
    ]);
  }

  function aclTable(rows, columns) {
    var table = el('table', { class: 'acl-table' });
    var head = el('tr', null, columns.map(function (c, i) {
      return el('th', { attrs: { scope: 'col' } }, [
        el('span', { class: 'th-label', text: c }),
        resizeHandle(table, c, i)
      ]);
    }));
    table.appendChild(el('caption', { class: 'visually-hidden', text: columns.join(', ') + ' table' }));
    table.appendChild(el('thead', null, [head]));
    table.appendChild(el('tbody', null, rows));
    return el('div', {
      class: 'table-scroll',
      attrs: { tabindex: '0', role: 'region', 'aria-label': columns.join(', ') + ' table, scrollable' }
    }, [table]);
  }

  var MIN_COL_WIDTH = 80;
  var KEY_RESIZE_STEP = 16;
  var KEY_RESIZE_STEP_LARGE = 48;

  function colNodes(table) { return table.querySelectorAll('colgroup > col'); }

  function colWidths(table) {
    return Array.prototype.map.call(colNodes(table), function (col) {
      return parseFloat(col.style.width) || 0;
    });
  }

  function setTableWidth(table) {
    var total = colWidths(table).reduce(function (a, b) { return a + b; }, 0);
    if (total > 0) table.style.width = total + 'px';
  }

  // Freeze the rendered widths once, so a later drag moves a single column and
  // the wrapper scrolls instead of the browser redistributing every column.
  function freezeColumnWidths(table) {
    if (table.querySelector('colgroup')) return;
    var ths = table.querySelectorAll('thead th');
    var group = document.createElement('colgroup');
    Array.prototype.forEach.call(ths, function (th) {
      var rect = th.getBoundingClientRect ? th.getBoundingClientRect() : null;
      var w = rect && rect.width ? Math.round(rect.width) : MIN_COL_WIDTH;
      var col = document.createElement('col');
      col.style.width = Math.max(MIN_COL_WIDTH, w) + 'px';
      group.appendChild(col);
    });
    table.insertBefore(group, table.firstChild);
    table.style.tableLayout = 'fixed';
    setTableWidth(table);
  }

  function columnWidth(table, index) {
    freezeColumnWidths(table);
    var col = colNodes(table)[index];
    return col ? (parseFloat(col.style.width) || MIN_COL_WIDTH) : MIN_COL_WIDTH;
  }

  function resizeColumn(table, index, width, handle) {
    freezeColumnWidths(table);
    var col = colNodes(table)[index];
    if (!col) return;
    var next = Math.max(MIN_COL_WIDTH, Math.round(width));
    col.style.width = next + 'px';
    setTableWidth(table);
    if (handle) handle.setAttribute('aria-valuenow', String(next));
  }

  // Back to the browser's automatic layout.
  function resetColumnWidths(table) {
    var group = table.querySelector('colgroup');
    if (group) table.removeChild(group);
    table.style.tableLayout = '';
    table.style.width = '';
    Array.prototype.forEach.call(table.querySelectorAll('.col-resize'), function (h) {
      h.removeAttribute('aria-valuenow');
    });
  }

  function resizeHandle(table, name, index) {
    var handle = el('span', {
      class: 'col-resize',
      attrs: {
        role: 'separator',
        tabindex: '0',
        'aria-orientation': 'vertical',
        'aria-label': 'Resize column ' + name + '. Use Left and Right arrows, Shift for a larger step.',
        'aria-valuemin': String(MIN_COL_WIDTH),
        'aria-valuemax': '10000'
      }
    });
    var drag = null;

    function onMove(ev) {
      if (!drag) return;
      resizeColumn(table, index, drag.width + (ev.clientX - drag.x), handle);
    }

    function endDrag() {
      drag = null;
      if (!window.addEventListener) return;
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', endDrag);
      window.removeEventListener('pointercancel', endDrag);
    }

    handle.addEventListener('pointerdown', function (ev) {
      if (ev.button !== undefined && ev.button !== 0) return;
      ev.preventDefault();
      ev.stopPropagation();
      drag = { x: ev.clientX, width: columnWidth(table, index) };
      if (window.addEventListener) {
        window.addEventListener('pointermove', onMove);
        window.addEventListener('pointerup', endDrag);
        window.addEventListener('pointercancel', endDrag);
      }
    });

    handle.addEventListener('keydown', function (ev) {
      var step = ev.shiftKey ? KEY_RESIZE_STEP_LARGE : KEY_RESIZE_STEP;
      if (ev.key === 'ArrowLeft') {
        ev.preventDefault();
        resizeColumn(table, index, columnWidth(table, index) - step, handle);
      } else if (ev.key === 'ArrowRight') {
        ev.preventDefault();
        resizeColumn(table, index, columnWidth(table, index) + step, handle);
      }
    });

    handle.addEventListener('dblclick', function (ev) {
      ev.preventDefault();
      resetColumnWidths(table);
    });

    // Report the real pixel width, not the clamped 0-100 default, so the
    // value is meaningful before the first keyboard resize as well as after.
    handle.addEventListener('focus', function () {
      handle.setAttribute('aria-valuenow', String(Math.round(columnWidth(table, index))));
    });

    return handle;
  }

  var treeEl = $('tree');
  var detailEl = $('detail-pane');
  var selectedNodeId = null;
  var rootsUl = null;
  var rootsReady = false;
  var rootsPending = null;
  var revealToken = 0;

  function loadChildrenPage(parentId) {
    var params = (parentId === undefined || parentId === null) ? {} : { parent_id: parentId };
    return fetchJSON(API.children, params).then(function (data) {
      if (Array.isArray(data)) return { children: data, truncated: false };
      return {
        children: arr(firstDefined([data], ['children', 'nodes', 'items', 'results', 'folders'])),
        truncated: !!(data && typeof data === 'object' && data.truncated === true)
      };
    });
  }

  // The list is capped server-side; say so instead of showing a partial list
  // as if it were complete.
  function truncationRow() {
    return el('li', { class: 'tree-item' }, [
      el('div', { class: 'tree-row' }, [
        el('span', { class: 'tree-toggle tree-toggle-empty', attrs: { 'aria-hidden': 'true' }, text: '\u00B7' }),
        el('span', {
          class: 'tree-state',
          attrs: { role: 'status' },
          text: 'More than 2,000 children; use path search to find omitted folders'
        })
      ])
    ]);
  }

  function loadChildrenInto(ul, parentId) {
    clear(ul);
    ul.dataset.loaded = 'true';
    ul.appendChild(el('li', { class: 'tree-state', text: 'Loading\u2026' }));
    // Returns the page on success and null on failure (after rendering the
    // inline error), so callers can await and chain the lazy load.
    return loadChildrenPage(parentId).then(function (page) {
      clear(ul);
      if (page.children.length) {
        page.children.forEach(function (k) { ul.appendChild(renderTreeNode(k)); });
      } else {
        ul.appendChild(el('li', { class: 'tree-state', text: 'No subfolders.' }));
      }
      if (page.truncated) ul.appendChild(truncationRow());
      return page;
    }, function (err) {
      clear(ul);
      ul.appendChild(el('li', null, [
        el('div', { class: 'state state-error', attrs: { role: 'alert' } }, [
          el('p', { text: 'Could not load subfolders: ' + err.message }),
          el('button', {
            class: 'button', type: 'button', text: 'Retry',
            onclick: function () { loadChildrenInto(ul, parentId); }
          })
        ])
      ]));
      return null;
    });
  }

  function setToggleState(toggle, name, expanded) {
    toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    toggle.setAttribute('aria-label', (expanded ? 'Collapse folder ' : 'Expand folder ') + name);
    toggle.textContent = expanded ? '\u25BE' : '\u25B8';
  }

  function renderTreeNode(v) {
    var id = nodeId(v);
    var name = nodeName(v);
    if (!name) name = id !== undefined ? 'Node ' + asText(id) : 'Unknown node';
    var hasKids = nodeHasChildren(v);
    var canExpand = (hasKids === undefined) ? true : !!hasKids;
    var li = el('li', { class: 'tree-item' });
    var row = el('div', { class: 'tree-row' });
    var childUl = null;

    if (canExpand && id !== undefined) {
      var childUlId = 'tree-children-' + id;
      childUl = el('ul', { class: 'tree-list', id: childUlId, hidden: true });
      var toggle = el('button', { class: 'tree-toggle', type: 'button' });
      setToggleState(toggle, name, false);
      toggle.setAttribute('aria-controls', childUlId);
      toggle.addEventListener('click', function () {
        var open = toggle.getAttribute('aria-expanded') === 'true';
        setToggleState(toggle, name, !open);
        childUl.hidden = open;
        if (!open && !childUl.dataset.loaded) {
          childUl.dataset.loaded = 'true';
          loadChildrenInto(childUl, id);
        }
      });
      row.appendChild(toggle);
    } else {
      row.appendChild(el('span', { class: 'tree-toggle tree-toggle-empty', attrs: { 'aria-hidden': 'true' }, text: '\u00B7' }));
    }

    var label = el('button', {
      class: 'node-select', type: 'button', text: name,
      data: { nodeId: id === undefined ? '' : asText(id) }
    });
    label.addEventListener('click', function () {
      if (id === undefined) {
        errorInto(detailEl, 'This item has no node id, so its details cannot be loaded.');
        return;
      }
      selectNode(id);
    });
    row.appendChild(label);
    li.appendChild(row);
    if (childUl) li.appendChild(childUl);
    return li;
  }

  function updateAriaCurrent() {
    Array.prototype.forEach.call(treeEl.querySelectorAll('.node-select'), function (b) {
      if (b.dataset.nodeId !== '' && String(b.dataset.nodeId) === String(selectedNodeId)) {
        b.setAttribute('aria-current', 'true');
      } else {
        b.removeAttribute('aria-current');
      }
    });
  }

  function loadRoots() {
    selectedNodeId = null;
    clear(treeEl);
    rootsUl = el('ul', { class: 'tree-list' });
    treeEl.appendChild(rootsUl);
    rootsReady = false;
    rootsPending = loadChildrenInto(rootsUl, undefined).then(function (page) {
      rootsReady = page !== null;
      rootsPending = null;
      return rootsReady;
    });
    return rootsPending;
  }

  // Reuse the roots already in the tree; only (re)load when there is nothing
  // loaded and nothing in flight. Resolves to true once roots are present.
  function ensureRoots() {
    if (rootsReady) return Promise.resolve(true);
    if (rootsPending) return rootsPending;
    return loadRoots();
  }

  function selectNode(id) {
    selectedNodeId = id;
    updateAriaCurrent();
    showNodeDetail(id);
  }

  // -- reveal a path-search result in the tree ----------------------------

  function treeButton(id) {
    var buttons = treeEl.querySelectorAll('.node-select');
    for (var i = 0; i < buttons.length; i++) {
      if (buttons[i].dataset.nodeId !== '' && buttons[i].dataset.nodeId === String(id)) {
        return buttons[i];
      }
    }
    return null;
  }

  function treeItemOf(button) {
    return button.closest ? button.closest('li.tree-item') : null;
  }

  // The <ul> holding a row's children, created on demand if the row was drawn
  // without one.
  function childListOf(button) {
    var li = treeItemOf(button);
    if (!li) return null;
    for (var i = 0; i < li.children.length; i++) {
      var child = li.children[i];
      if (child.tagName === 'UL' && child.className.indexOf('tree-list') !== -1) return child;
    }
    var ul = el('ul', { class: 'tree-list', hidden: true });
    li.appendChild(ul);
    return ul;
  }

  // Open a row and await its children, so the next chain step can find them.
  function expandRow(button) {
    var li = treeItemOf(button);
    var ul = childListOf(button);
    if (!li || !ul) return Promise.reject(new Error('This tree row cannot be expanded.'));
    ul.hidden = false;
    var toggle = li.querySelector('button.tree-toggle');
    if (toggle) setToggleState(toggle, button.textContent, true);
    if (ul.dataset.loaded === 'true') return Promise.resolve();
    return loadChildrenInto(ul, button.dataset.nodeId).then(function (page) {
      if (page === null) {
        throw new Error('Could not load subfolders of ' + button.textContent + '.');
      }
    });
  }

  // Expand one parent, then make sure the known chain child is in its list.
  // The children list can be truncated server-side, so insert the node the
  // chain already knows about rather than failing the reveal.
  function revealStep(token, parent, child) {
    return function () {
      if (token !== revealToken) return;
      var parentButton = treeButton(nodeId(parent));
      if (!parentButton) {
        throw new Error('Folder ' + (nodeName(parent) || nodeId(parent)) + ' is not in the tree.');
      }
      return expandRow(parentButton).then(function () {
        if (token !== revealToken) return;
        var childId = nodeId(child);
        if (!treeButton(childId)) {
          var ul = childListOf(parentButton);
          if (ul) ul.appendChild(renderTreeNode(child));
        }
      });
    };
  }

  function revealSlot(container) {
    var slot = container.querySelector('.reveal-status');
    if (!slot) {
      slot = el('div', { class: 'reveal-status' });
      container.insertBefore(slot, container.firstChild);
    }
    return slot;
  }

  function revealLoading(container, text) {
    var slot = revealSlot(container);
    clear(slot);
    slot.appendChild(el('p', { class: 'state state-loading', attrs: { role: 'status' }, text: text }));
  }

  function revealDone(container) {
    var slot = container.querySelector('.reveal-status');
    if (slot && slot.parentNode) slot.parentNode.removeChild(slot);
  }

  function revealError(container, text, retry) {
    var slot = revealSlot(container);
    clear(slot);
    slot.appendChild(el('div', { class: 'state state-error', attrs: { role: 'alert' } }, [
      el('p', { text: text }),
      retry ? el('button', { class: 'button', type: 'button', text: 'Retry', onclick: retry }) : null
    ]));
  }

  // Fetch the ancestor chain once, then expand branch by branch until the
  // target is selected. A later click supersedes an earlier one via the token.
  function revealNodeInTree(result) {
    var container = $('path-search-results');
    var id = nodeId(result);
    var label = (result && typeof result === 'object')
      ? asText(pick(result, ['path', 'name', 'label', 'value', 'full_path']))
      : asText(result);
    if (id === undefined) {
      revealError(container, 'This result has no node id, so it cannot be revealed in the tree.');
      return Promise.resolve();
    }
    var token = ++revealToken;
    revealLoading(container, 'Revealing ' + label + '\u2026');
    return fetchJSON(API.ancestors, { id: id }).then(function (data) {
      if (token !== revealToken) return;
      var chain = arr(firstDefined([data], ['ancestors', 'chain', 'nodes', 'items', 'results']));
      if (!chain.length) throw new Error('The server returned no ancestor chain.');
      return ensureRoots().then(function (ok) {
        if (token !== revealToken) return;
        if (!ok) throw new Error('The tree could not be loaded.');
        // The chain starts at a root, which may be missing from a truncated
        // root list; add it before expanding anything.
        if (!treeButton(nodeId(chain[0])) && rootsUl) rootsUl.appendChild(renderTreeNode(chain[0]));
        var seq = Promise.resolve();
        for (var i = 0; i < chain.length - 1; i++) {
          seq = seq.then(revealStep(token, chain[i], chain[i + 1]));
        }
        return seq;
      });
    }).then(function () {
      if (token !== revealToken) return;
      selectNode(id);
      var button = treeButton(id);
      if (!button) throw new Error('Node ' + id + ' is not in the tree.');
      button.focus();
      if (typeof button.scrollIntoView === 'function') {
        button.scrollIntoView({ block: 'center', inline: 'nearest' });
      }
      revealDone(container);
    }, function (err) {
      if (token !== revealToken) return;
      revealError(container, 'Could not reveal this result: ' + err.message, function () {
        revealNodeInTree(result);
      });
    });
  }

  function showNodeDetail(id) {
    loadingInto(detailEl, 'Loading node ' + asText(id) + '\u2026');
    fetchJSON(API.node, { id: id }).then(function (data) {
      renderNodeDetail(data, id);
    }, function (err) {
      errorInto(detailEl, 'Could not load this node: ' + err.message, function () { showNodeDetail(id); });
    });
  }

  function renderNodeDetail(data, fallbackId) {
    var node = (data && typeof data === 'object' && data.node && typeof data.node === 'object') ? data.node : data;
    var sources = [data, node];
    var aces = arr(firstDefined(sources, ['aces', 'entries', 'acl']));
    var errors = arr(firstDefined(sources, ['scan_errors', 'errors']));

    clear(detailEl);
    var article = el('article', { class: 'detail' });

    var title = nodeName(node) || ('Node ' + asText(fallbackId));
    var path = asText(pick(node, ['path', 'full_path']));
    article.appendChild(el('header', { class: 'detail-header' }, [
      el('h2', { class: 'detail-title', text: title }),
      path && path !== title ? el('p', { class: 'detail-path', text: path }) : null
    ]));

    var denyCount = aces.filter(function (a) { return aceEffect(a) === 'deny'; }).length;
    var unresolvedCount = aces.filter(function (a) { return isUnresolved(a); }).length;
    article.appendChild(el('p', { class: 'badge-row' }, [
      badge(aces.length + (aces.length === 1 ? ' ACL entry' : ' ACL entries'), 'info'),
      denyCount ? badge(denyCount + ' deny', 'danger', 'This object has entries that deny access') : null,
      inheritanceDisabled(node) ? badge('Inheritance disabled', 'warn', 'Entries are not inherited from the parent object') : null,
      unresolvedCount ? badge(unresolvedCount + ' unresolved', 'warn', 'No account name was resolved for these entries') : null,
      errors.length ? badge(errors.length + (errors.length === 1 ? ' scan error' : ' scan errors'), 'danger') : null
    ]));

    var metaSpec = [
      ['Owner', ['owner', 'owner_name', 'uname']],
      ['Group', ['group', 'group_name', 'gname']],
      ['Mode', ['mode', 'perm', 'permissions_mode']],
      ['Type', ['type', 'kind', 'node_type']],
      ['Size', ['size', 'bytes']],
      ['Modified', ['mtime', 'modified', 'mtime_iso', 'updated']],
      ['Children', ['child_count', 'children_count']],
      ['Filesystem', ['device', 'fs', 'filesystem', 'mount']],
      ['Node id', ['id', 'node_id']]
    ];
    var used = {};
    var metaRows = [];
    metaSpec.forEach(function (spec) {
      var found;
      for (var i = 0; i < spec[1].length; i++) {
        if (used[spec[1][i]]) continue;
        if (!node || node[spec[1][i]] === undefined) continue;
        found = spec[1][i];
        break;
      }
      if (found === undefined) return;
      used[found] = true;
      metaRows.push([spec[0], asText(node[found])]);
    });
    if (node && typeof node === 'object') {
      Object.keys(node).forEach(function (k) {
        if (used[k] || EXCLUDED_NODE_KEYS[k]) return;
        var v = node[k];
        if (v === undefined || v === null || typeof v === 'object') return;
        used[k] = true;
        metaRows.push([k.replace(/_/g, ' '), asText(v)]);
      });
    }
    var metaSection = el('section', { class: 'detail-section' }, [
      el('h3', { class: 'section-title', text: 'Metadata' })
    ]);
    if (!metaRows.length) {
      metaSection.appendChild(el('p', { class: 'state state-empty', text: 'No metadata reported for this object.' }));
    } else {
      var dl = el('dl', { class: 'meta-list' });
      metaRows.forEach(function (pair) {
        dl.appendChild(el('dt', { text: pair[0] }));
        dl.appendChild(el('dd', { text: pair[1] }));
      });
      metaSection.appendChild(dl);
    }
    article.appendChild(metaSection);

    var aclSection = el('section', { class: 'detail-section' }, [
      el('h3', { class: 'section-title', text: 'Access control entries' }),
      el('p', {
        class: 'section-note',
        text: 'Inheritance: ' + (inheritanceDisabled(node)
          ? 'disabled for this object; entries come from this object itself.'
          : 'entries may be inherited from the parent object.')
      })
    ]);
    if (!aces.length) {
      aclSection.appendChild(el('p', { class: 'state state-empty', text: 'No ACL entries reported for this object.' }));
    } else {
      aclSection.appendChild(aclTable(aces.map(function (a) {
        var effect = aceEffect(a);
        var flags = [];
        var inheritedFrom = pick(a, ['inherited_from', 'inheritedFrom', 'from']);
        if (inheritedFrom !== undefined) flags.push('from ' + asText(inheritedFrom));
        var extra = pick(a, ['flags', 'note', 'reason']);
        if (extra !== undefined) flags.push(asText(extra));
        return el('tr', { class: effect === 'deny' ? 'row-deny' : null }, [
          principalCell(a),
          el('td', null, [effectBadge(effect)]),
          rightsCell(a),
          el('td', null, [sourceBadge(aceSource(a))]),
          el('td', { text: flags.length ? flags.join('; ') : '-' })
        ]);
      }), ['Principal', 'Effect', 'Rights', 'Source', 'Flags']));
    }
    article.appendChild(aclSection);

    var errSection = el('section', { class: 'detail-section' }, [
      el('h3', { class: 'section-title', text: 'Scan errors' })
    ]);
    if (!errors.length) {
      errSection.appendChild(el('p', { class: 'state state-empty', text: 'No scan errors for this object.' }));
    } else {
      errSection.appendChild(el('ul', { class: 'error-list' }, errors.map(function (e) {
        var msg = (e && typeof e === 'object')
          ? (errorMessage(e) || asText(e))
          : asText(e);
        return el('li', { class: 'error-item', text: msg });
      })));
    }
    article.appendChild(errSection);

    detailEl.appendChild(article);
  }

  function runPathSearch(q) {
    var container = $('path-search-results');
    container.hidden = false;
    loadingInto(container, 'Searching paths\u2026');
    fetchJSON(API.searchPaths, { q: q, limit: SEARCH_LIMIT }).then(function (data) {
      var list = Array.isArray(data) ? data : arr(firstDefined([data], ['results', 'paths', 'items', 'matches']));
      clear(container);
      if (!list.length) {
        container.appendChild(el('p', { class: 'state state-empty', text: 'No paths matched "' + q + '".' }));
        return;
      }
      container.appendChild(el('ul', { class: 'result-list' }, list.map(function (r) {
        var id = (r && typeof r === 'object') ? pick(r, ['id', 'node_id', 'nodeId']) : undefined;
        var label = (r && typeof r === 'object')
          ? asText(pick(r, ['path', 'name', 'label', 'value', 'full_path']))
          : asText(r);
        var li = el('li', { class: 'result-item' });
        if (id !== undefined) {
          li.appendChild(el('button', {
            class: 'link-button', type: 'button', text: label,
            onclick: function () { revealNodeInTree(r); }
          }));
        } else {
          li.appendChild(el('span', { class: 'result-static', text: label }));
        }
        return li;
      })));
    }, function (err) {
      errorInto(container, 'Path search failed: ' + err.message, function () { runPathSearch(q); });
    });
  }

  var principalState = { key: undefined, label: '', offset: 0, items: [], hasMore: false };

  function principalKey(p) {
    if (p === undefined || p === null) return undefined;
    if (typeof p === 'object') return pick(p, ['key', 'principal_key', 'principalKey', 'id', 'sid', 'name']);
    return p;
  }

  function runPrincipalSearch(q) {
    var container = $('principal-search-results');
    container.hidden = false;
    loadingInto(container, 'Searching principals\u2026');
    fetchJSON(API.searchPrincipals, { q: q, limit: SEARCH_LIMIT }).then(function (data) {
      var list = Array.isArray(data) ? data : arr(firstDefined([data], ['results', 'principals', 'items', 'matches']));
      clear(container);
      if (!list.length) {
        container.appendChild(el('p', { class: 'state state-empty', text: 'No principals matched "' + q + '".' }));
        return;
      }
      container.appendChild(el('ul', { class: 'result-list' }, list.map(function (p) {
        var key = principalKey(p);
        var label = (p && typeof p === 'object')
          ? asText(pick(p, ['name', 'label', 'principal', 'sid', 'key']))
          : asText(p);
        var kind = (p && typeof p === 'object') ? pick(p, ['type', 'kind', 'principal_type', 'category']) : undefined;
        var li = el('li', { class: 'result-item' });
        if (key !== undefined) {
          li.appendChild(el('button', {
            class: 'link-button', type: 'button', text: label,
            onclick: function () { selectPrincipal(key, label); }
          }));
        } else {
          li.appendChild(el('span', { class: 'result-static', text: label }));
        }
        if (kind) li.appendChild(badge(asText(kind), 'muted'));
        return li;
      })));
    }, function (err) {
      errorInto(container, 'Principal search failed: ' + err.message, function () { runPrincipalSearch(q); });
    });
  }

  function selectPrincipal(key, label) {
    principalState = { key: key, label: label, offset: 0, items: [], hasMore: false };
    loadPrincipalPage();
  }

  function loadPrincipalPage() {
    var detail = $('principal-detail');
    if (principalState.key === undefined) return;
    loadingInto(detail, 'Loading ACL entries for ' + principalState.label + '\u2026');
    fetchJSON(API.principal, {
      key: principalState.key,
      limit: PRINCIPAL_PAGE,
      offset: principalState.offset
    }).then(function (data) {
      var list = Array.isArray(data) ? data : arr(firstDefined([data], ['entries', 'results', 'items', 'acls', 'aces', 'objects']));
      principalState.items = principalState.items.concat(list);
      principalState.hasMore = list.length === PRINCIPAL_PAGE;
      principalState.offset = principalState.items.length;
      renderPrincipalDetail();
    }, function (err) {
      errorInto(detail, 'Could not load ACL entries: ' + err.message, function () { loadPrincipalPage(); });
    });
  }

  function entryObjectLabel(e) {
    if (e && typeof e === 'object') {
      var v = pick(e, ['path', 'node_path', 'object_path', 'object', 'target', 'node']);
      if (v !== undefined && typeof v === 'object') return asText(pick(v, ['path', 'name', 'label', 'id']) || v);
      if (v !== undefined) return asText(v);
      var id = pick(e, ['node_id', 'id']);
      if (id !== undefined) return 'Node ' + asText(id);
    }
    return '(unknown object)';
  }

  function renderPrincipalDetail() {
    var detail = $('principal-detail');
    clear(detail);
    var article = el('article', { class: 'detail' });

    article.appendChild(el('header', { class: 'detail-header' }, [
      el('h2', { class: 'detail-title', text: 'Direct ACL entries for ' + principalState.label }),
      el('p', {
        class: 'detail-path',
        text: principalState.items.length + (principalState.items.length === 1 ? ' entry' : ' entries')
          + ' loaded' + (principalState.hasMore ? ', more available' : '')
      })
    ]));

    article.appendChild(el('p', { class: 'notice notice-inline' }, [
      badge('Direct entries only', 'info'),
      el('span', { text: ' Objects that name this principal directly in their access control list. This is not effective access.' })
    ]));

    var section = el('section', { class: 'detail-section' }, [
      el('h3', { class: 'section-title', text: 'Objects naming this principal' })
    ]);
    if (!principalState.items.length) {
      section.appendChild(el('p', { class: 'state state-empty', text: 'No ACL entries name this principal directly.' }));
    } else {
      section.appendChild(aclTable(principalState.items.map(function (e) {
        var effect = aceEffect(e);
        var flags = [];
        var extra = pick(e, ['flags', 'note', 'reason']);
        if (extra !== undefined) flags.push(asText(extra));
        return el('tr', { class: effect === 'deny' ? 'row-deny' : null }, [
          el('td', { class: 'cell-object', text: entryObjectLabel(e) }),
          el('td', null, [effectBadge(effect)]),
          rightsCell(e),
          el('td', null, [sourceBadge(aceSource(e))]),
          el('td', { text: flags.length ? flags.join('; ') : '-' })
        ]);
      }), ['Object', 'Effect', 'Rights', 'Source', 'Flags']));
    }
    article.appendChild(section);

    if (principalState.hasMore) {
      article.appendChild(el('p', { class: 'detail-actions' }, [
        el('button', { class: 'button', type: 'button', text: 'Load more', onclick: loadPrincipalPage })
      ]));
    }

    detail.appendChild(article);
  }

  function loadStatus() {
    var bar = $('status-bar');
    bar.className = 'status-bar';
    bar.textContent = 'Loading status\u2026';
    fetchJSON(API.status).then(function (data) {
      if (typeof data === 'string') { bar.textContent = data; return; }
      var spec = [
        ['Root', ['root', 'root_path', 'path']],
        ['Host', ['host', 'hostname']],
        ['Scanned', ['scanned_at', 'generated_at', 'scan_time', 'date']],
        ['Objects', ['node_count', 'nodes', 'objects', 'file_count']],
        ['Principals', ['principal_count', 'principals']],
        ['Errors', ['error_count', 'scan_errors', 'errors']],
        ['Version', ['version']]
      ];
      var used = {};
      var parts = [];
      spec.forEach(function (pair) {
        for (var i = 0; i < pair[1].length; i++) {
          var k = pair[1][i];
          if (used[k]) continue;
          var v = data ? data[k] : undefined;
          if (v === undefined || v === null || typeof v === 'object') continue;
          used[k] = true;
          parts.push(pair[0] + ': ' + asText(v));
          break;
        }
      });
      bar.textContent = parts.length ? parts.join('  |  ') : 'Status loaded.';
    }, function (err) {
      bar.className = 'status-bar status-error';
      bar.textContent = 'Status unavailable: ' + err.message;
    });
  }

  var tabButtons = Array.prototype.slice.call(document.querySelectorAll('.tab'));
  var panels = { explore: $('panel-explore'), principals: $('panel-principals') };

  function activateTab(view, moveFocus) {
    tabButtons.forEach(function (t) {
      var on = t.dataset.view === view;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      if (on && moveFocus) t.focus();
    });
    Object.keys(panels).forEach(function (k) { panels[k].hidden = (k !== view); });
    if (panels[view]) panels[view].focus();
  }

  function initTabs() {
    tabButtons.forEach(function (t, i) {
      t.addEventListener('click', function () { activateTab(t.dataset.view); });
      t.addEventListener('keydown', function (ev) {
        var next = null;
        if (ev.key === 'ArrowRight') next = tabButtons[(i + 1) % tabButtons.length];
        else if (ev.key === 'ArrowLeft') next = tabButtons[(i - 1 + tabButtons.length) % tabButtons.length];
        else if (ev.key === 'Home') next = tabButtons[0];
        else if (ev.key === 'End') next = tabButtons[tabButtons.length - 1];
        if (next) { ev.preventDefault(); activateTab(next.dataset.view, true); }
      });
    });
  }

  function initSearchForms() {
    $('path-search-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var q = $('path-search-input').value.trim();
      var container = $('path-search-results');
      if (!q) { container.hidden = true; clear(container); return; }
      runPathSearch(q);
    });

    $('principal-search-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var q = $('principal-search-input').value.trim();
      var container = $('principal-search-results');
      if (!q) { container.hidden = true; clear(container); return; }
      runPrincipalSearch(q);
    });
  }

  function initTreeKeys() {
    treeEl.addEventListener('keydown', function (ev) {
      var buttons = Array.prototype.slice.call(treeEl.querySelectorAll('button'));
      var idx = buttons.indexOf(document.activeElement);
      if (idx === -1) return;
      var current = buttons[idx];
      if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        buttons[Math.min(idx + 1, buttons.length - 1)].focus();
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        buttons[Math.max(idx - 1, 0)].focus();
      } else if (ev.key === 'Home') {
        ev.preventDefault();
        buttons[0].focus();
      } else if (ev.key === 'End') {
        ev.preventDefault();
        buttons[buttons.length - 1].focus();
      } else if (ev.key === 'ArrowRight') {
        if (current.classList.contains('tree-toggle') && current.getAttribute('aria-expanded') === 'false') {
          ev.preventDefault();
          current.click();
        }
      } else if (ev.key === 'ArrowLeft') {
        if (current.classList.contains('tree-toggle') && current.getAttribute('aria-expanded') === 'true') {
          ev.preventDefault();
          current.click();
        }
      }
    });
  }

  function init() {
    initTabs();
    initSearchForms();
    initTreeKeys();
    $('tree-refresh').addEventListener('click', loadRoots);
    loadStatus();
    loadRoots();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
