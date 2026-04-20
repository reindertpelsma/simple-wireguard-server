import { useCallback, useEffect, useRef, useState } from 'react';
import { GripVertical, Plus, ShieldAlert, Trash2, X } from 'lucide-react';
import { api } from '../lib/api';

const PROTO_OPTIONS = ['any', 'tcp', 'udp', 'icmp'];

// Token types and their display colours
const TOKEN_COLORS = {
  user: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  tag:  'bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200',
  peer: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  cidr: 'bg-[var(--surface-soft)] text-[var(--ink)] border border-[var(--border)]',
};
const TOKEN_LABELS = { user: 'user', tag: 'group', peer: 'peer', cidr: '' };

function guessTokenType(value) {
  if (value.startsWith('user:')) return { type: 'user', value: value.slice(5) };
  if (value.startsWith('tag:'))  return { type: 'tag',  value: value.slice(4) };
  if (value.startsWith('peer:')) return { type: 'peer', value: value.slice(5) };
  return { type: 'cidr', value };
}

// Parse the combined fields from an ACL rule into a token list
function ruleToTokens(rule, side) {
  const tokens = [];
  const prefix = side === 'src' ? 'Src' : 'Dst';
  for (const cidr of (rule[side] || '').split(',').map(s => s.trim()).filter(Boolean)) {
    tokens.push({ type: 'cidr', value: cidr });
  }
  for (const u of (rule[`${side === 'src' ? 'src' : 'dst'}_users`] || '').split(',').map(s => s.trim()).filter(Boolean)) {
    tokens.push({ type: 'user', value: u });
  }
  for (const t of (rule[`${side === 'src' ? 'src' : 'dst'}_tags`] || '').split(',').map(s => s.trim()).filter(Boolean)) {
    tokens.push({ type: 'tag', value: t });
  }
  for (const p of (rule[`${side === 'src' ? 'src' : 'dst'}_peers`] || '').split(',').map(s => s.trim()).filter(Boolean)) {
    tokens.push({ type: 'peer', value: p });
  }
  void prefix;
  return tokens;
}

function tokensToFields(tokens, side) {
  const cidrs = [], users = [], tags = [], peers = [];
  for (const t of tokens) {
    if (t.type === 'cidr') cidrs.push(t.value);
    else if (t.type === 'user') users.push(t.value);
    else if (t.type === 'tag') tags.push(t.value);
    else if (t.type === 'peer') peers.push(t.value);
  }
  const p = side === 'src' ? 'src' : 'dst';
  return {
    [p]: cidrs.join(', '),
    [`${p}_users`]: users.join(', '),
    [`${p}_tags`]: tags.join(', '),
    [`${p}_peers`]: peers.join(', '),
  };
}

// Token input component (Gmail-style chips)
function TokenInput({ tokens, onChange, placeholder }) {
  const [input, setInput] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [sugIdx, setSugIdx] = useState(-1);
  const inputRef = useRef(null);
  const debounceRef = useRef(null);

  const fetchSuggestions = useCallback(async (q) => {
    if (!q) { setSuggestions([]); return; }
    try {
      const res = await api.searchACLTokens(q);
      setSuggestions(res || []);
    } catch {
      setSuggestions([]);
    }
  }, []);

  const addToken = (type, value) => {
    value = value.trim();
    if (!value) return;
    if (tokens.some(t => t.type === type && t.value === value)) return;
    onChange([...tokens, { type, value }]);
    setInput('');
    setSuggestions([]);
    setSugIdx(-1);
  };

  const tryAddRaw = (raw) => {
    raw = raw.trim();
    if (!raw) return;
    const { type, value } = guessTokenType(raw);
    addToken(type, value);
  };

  const handleKey = (e) => {
    if (e.key === 'Backspace' && input === '' && tokens.length > 0) {
      onChange(tokens.slice(0, -1));
      return;
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); setSugIdx(i => Math.min(i + 1, suggestions.length - 1)); return; }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSugIdx(i => Math.max(i - 1, 0)); return; }
    if ((e.key === 'Enter' || e.key === ' ' || e.key === 'Tab') && suggestions.length > 0 && sugIdx >= 0) {
      e.preventDefault();
      const s = suggestions[sugIdx];
      addToken(s.type, s.value);
      return;
    }
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (suggestions.length === 1) { addToken(suggestions[0].type, suggestions[0].value); return; }
      tryAddRaw(input);
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      tryAddRaw(input);
    }
  };

  const handleChange = (e) => {
    const v = e.target.value;
    setInput(v);
    setSugIdx(-1);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchSuggestions(v), 150);
  };

  return (
    <div
      className="relative min-h-[42px] w-full cursor-text rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 focus-within:border-[var(--accent)] focus-within:ring-2 focus-within:ring-[var(--accent)]/20"
      onClick={() => inputRef.current?.focus()}
    >
      <div className="flex flex-wrap gap-1">
        {tokens.map((t, i) => (
          <span
            key={`${t.type}-${t.value}-${i}`}
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold ${TOKEN_COLORS[t.type]}`}
          >
            {TOKEN_LABELS[t.type] && <span className="opacity-60">{TOKEN_LABELS[t.type]}:</span>}
            {t.value}
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onChange(tokens.filter((_, j) => j !== i)); }}
              className="ml-0.5 opacity-60 hover:opacity-100"
            >
              <X size={10} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          className="min-w-20 flex-1 bg-transparent text-sm outline-none placeholder:text-[var(--muted)]"
          value={input}
          onChange={handleChange}
          onKeyDown={handleKey}
          onBlur={() => setTimeout(() => { setSuggestions([]); setSugIdx(-1); }, 150)}
          placeholder={tokens.length === 0 ? placeholder : ''}
        />
      </div>
      {suggestions.length > 0 && (
        <ul className="absolute left-0 top-full z-50 mt-1 w-full max-h-48 overflow-y-auto rounded-2xl border border-[var(--border)] bg-[var(--panel)] py-1 shadow-xl">
          {suggestions.map((s, i) => (
            <li
              key={`${s.type}-${s.value}`}
              className={`flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm ${i === sugIdx ? 'bg-[var(--accent)]/10' : 'hover:bg-[var(--surface-soft)]'}`}
              onMouseDown={(e) => { e.preventDefault(); addToken(s.type, s.value); }}
            >
              <span className={`rounded-full px-1.5 py-0.5 text-xs font-bold ${TOKEN_COLORS[s.type]}`}>{s.type}</span>
              <span className="font-medium">{s.value}</span>
              {s.label !== s.value && <span className="text-xs text-[var(--muted)]">{s.label}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// Single rule row with drag handle
function RuleRow({ rule, onDelete, onEdit, dragHandleProps }) {
  const srcTokens = ruleToTokens(rule, 'src');
  const dstTokens = ruleToTokens(rule, 'dst');

  return (
    <div className="group flex items-start gap-2 rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-3">
      <button
        type="button"
        className="mt-0.5 cursor-grab text-[var(--muted)] opacity-40 group-hover:opacity-70 active:cursor-grabbing"
        {...dragHandleProps}
        title="Drag to reorder"
      >
        <GripVertical size={16} />
      </button>

      <div className="flex-1 grid gap-1.5 md:grid-cols-[auto_1fr_1fr_auto_auto_auto]">
        <span className={`self-start rounded-full px-2 py-0.5 text-xs font-bold uppercase ${rule.action === 'deny' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900 dark:text-emerald-300'}`}>
          {rule.action}
        </span>

        <div className="flex flex-wrap gap-1 text-xs">
          {srcTokens.length === 0
            ? <span className="text-[var(--muted)]">any source</span>
            : srcTokens.map((t, i) => (
              <span key={i} className={`rounded-full px-2 py-0.5 font-semibold ${TOKEN_COLORS[t.type]}`}>
                {TOKEN_LABELS[t.type] && <span className="opacity-60">{TOKEN_LABELS[t.type]}: </span>}
                {t.value}
              </span>
            ))
          }
        </div>

        <div className="flex flex-wrap gap-1 text-xs">
          {dstTokens.length === 0
            ? <span className="text-[var(--muted)]">any dest</span>
            : dstTokens.map((t, i) => (
              <span key={i} className={`rounded-full px-2 py-0.5 font-semibold ${TOKEN_COLORS[t.type]}`}>
                {TOKEN_LABELS[t.type] && <span className="opacity-60">{TOKEN_LABELS[t.type]}: </span>}
                {t.value}
              </span>
            ))
          }
        </div>

        <span className="self-start rounded bg-[var(--surface-soft)] px-2 py-0.5 font-mono text-xs">
          {rule.proto || 'any'}
        </span>
        <span className="self-start text-xs text-[var(--muted)]">{rule.dport || ''}</span>
      </div>

      <div className="flex gap-1">
        <button type="button" onClick={() => onEdit(rule)} className="ghost-button text-xs">Edit</button>
        <button type="button" onClick={() => onDelete(rule.id)} className="ghost-button ghost-button-danger">
          <Trash2 size={14} />
        </button>
      </div>
    </div>
  );
}

const EMPTY_RULE = { action: 'allow', src: '', src_users: '', src_tags: '', src_peers: '', dst: '', dst_users: '', dst_tags: '', dst_peers: '', proto: 'any', dport: '' };

function RuleForm({ initial, onSave, onCancel, listName }) {
  const [srcTokens, setSrcTokens] = useState(() => initial ? ruleToTokens(initial, 'src') : []);
  const [dstTokens, setDstTokens] = useState(() => initial ? ruleToTokens(initial, 'dst') : []);
  const [form, setForm] = useState(() => initial ? { ...initial } : { ...EMPTY_RULE });

  const handleSubmit = (e) => {
    e.preventDefault();
    const srcFields = tokensToFields(srcTokens, 'src');
    const dstFields = tokensToFields(dstTokens, 'dst');
    onSave({ ...form, list_name: listName, ...srcFields, ...dstFields, proto: form.proto === 'any' ? '' : form.proto });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-1.5">
          <label className="field-label">Action</label>
          <select className="select-field" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </div>
        <div className="space-y-1.5">
          <label className="field-label">Protocol</label>
          <select className="select-field" value={form.proto || 'any'} onChange={e => setForm({ ...form, proto: e.target.value })}>
            {PROTO_OPTIONS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="space-y-1.5">
          <label className="field-label">Destination port</label>
          <input className="input-field" placeholder="80, 443, 8000-8999" value={form.dport || ''} onChange={e => setForm({ ...form, dport: e.target.value })} />
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="field-label">Source <span className="font-normal text-[var(--muted)] normal-case">— users, groups, peers, IPs/CIDRs</span></label>
        <TokenInput tokens={srcTokens} onChange={setSrcTokens} placeholder="any source — type to search or enter an IP/CIDR" />
      </div>

      <div className="space-y-1.5">
        <label className="field-label">Destination <span className="font-normal text-[var(--muted)] normal-case">— users, groups, peers, IPs/CIDRs</span></label>
        <TokenInput tokens={dstTokens} onChange={setDstTokens} placeholder="any destination — type to search or enter an IP/CIDR" />
      </div>

      <div className="flex justify-end gap-2">
        {onCancel && <button type="button" onClick={onCancel} className="ghost-button">Cancel</button>}
        <button type="submit" className="primary-button">
          <Plus size={15} />
          <span>{initial ? 'Save changes' : 'Add rule'}</span>
        </button>
      </div>
    </form>
  );
}

export default function ACLsTab() {
  const [acls, setACLs] = useState([]);
  const [defaults, setDefaults] = useState({ inbound: 'allow', outbound: 'allow', relay: 'deny' });
  const [activeList, setActiveList] = useState('relay');
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [orderedIds, setOrderedIds] = useState(null); // null = not dirty
  const [dragging, setDragging] = useState(null);
  const [dragOver, setDragOver] = useState(null);

  const fetchACLs = useCallback(async function() {
    try {
      const [data, config] = await Promise.all([api.getACLs(), api.getAdminConfig()]);
      setACLs(data);
      setDefaults({
        inbound: config.acl_inbound_default || 'allow',
        outbound: config.acl_outbound_default || 'allow',
        relay: config.acl_relay_default || 'deny',
      });
    } catch (err) {
      console.error(err);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.getACLs(), api.getAdminConfig()])
      .then(([data, config]) => {
        if (cancelled) return;
        setACLs(data);
        setDefaults({
          inbound: config.acl_inbound_default || 'allow',
          outbound: config.acl_outbound_default || 'allow',
          relay: config.acl_relay_default || 'deny',
        });
      })
      .catch((err) => console.error(err));
    return () => {
      cancelled = true;
    };
  }, []);

  const listRules = acls.filter(a => a.list_name === activeList);
  const displayRules = orderedIds
    ? orderedIds.map(id => listRules.find(r => r.id === id)).filter(Boolean)
    : listRules;

  const saveDefaults = async () => {
    try {
      await api.updateGlobalConfig({
        acl_inbound_default: defaults.inbound,
        acl_outbound_default: defaults.outbound,
        acl_relay_default: defaults.relay,
      });
    } catch (err) {
      alert(err.message);
    }
  };

  const handleCreate = async (data) => {
    try {
      await api.createACL(data);
      setShowForm(false);
      setOrderedIds(null);
      await fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdate = async (data) => {
    try {
      await api.updateACL(data.id, data);
      setEditingRule(null);
      setOrderedIds(null);
      await fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this rule?')) return;
    try {
      await api.deleteACL(id);
      setOrderedIds(null);
      await fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  const saveOrder = async () => {
    if (!orderedIds) return;
    const items = orderedIds.map((id, idx) => ({ id, sort_order: idx }));
    try {
      await api.reorderACLs(items);
      setOrderedIds(null);
      await fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  // Drag-to-reorder
  const handleDragStart = (id) => setDragging(id);
  const handleDragEnd = () => { setDragging(null); setDragOver(null); };
  const handleDragOver = (e, id) => { e.preventDefault(); setDragOver(id); };
  const handleDrop = (targetId) => {
    if (dragging === null || dragging === targetId) return;
    const base = orderedIds || displayRules.map(r => r.id);
    const from = base.indexOf(dragging);
    const to = base.indexOf(targetId);
    if (from < 0 || to < 0) return;
    const next = [...base];
    next.splice(from, 1);
    next.splice(to, 0, dragging);
    setOrderedIds(next);
    setDragOver(null);
  };

  const LISTS = [
    { id: 'inbound', label: 'Inbound', desc: 'WireGuard → server/host' },
    { id: 'outbound', label: 'Outbound', desc: 'Server → WireGuard' },
    { id: 'relay', label: 'Relay', desc: 'Peer ↔ peer forwarding' },
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm text-[var(--muted)]">
        ACL changes take effect immediately — rules are pushed live to the daemon without a restart.
      </div>

      {/* Defaults */}
      <section className="panel p-6">
        <div className="mb-4 flex items-center gap-3">
          <div className="brand-badge"><ShieldAlert size={18} /></div>
          <div>
            <span className="eyebrow">ACL Defaults</span>
            <h3 className="text-2xl font-black tracking-tight">Default actions</h3>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {LISTS.map(({ id, label, desc }) => (
            <div key={id} className="space-y-1.5">
              <label className="field-label">{label} <span className="normal-case font-normal text-[var(--muted)]">— {desc}</span></label>
              <select
                className="select-field"
                value={defaults[id]}
                onChange={e => setDefaults(d => ({ ...d, [id]: e.target.value }))}
              >
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
          ))}
        </div>
        <div className="mt-4">
          <button type="button" onClick={saveDefaults} className="primary-button"><span>Save defaults</span></button>
        </div>
      </section>

      {/* Tab strip */}
      <div className="flex gap-2">
        {LISTS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => { setActiveList(id); setShowForm(false); setEditingRule(null); setOrderedIds(null); }}
            className={`tab-pill ${activeList === id ? 'tab-pill-active' : ''}`}
          >
            {label}
            <span className="ml-1 rounded-full bg-[var(--border)] px-1.5 py-0.5 text-xs">
              {acls.filter(a => a.list_name === id).length}
            </span>
          </button>
        ))}
      </div>

      {/* Rules list */}
      <section className="space-y-2">
        {displayRules.length === 0 && !showForm && (
          <div className="state-shell py-10 text-[var(--muted)]">No {activeList} rules — default is <strong>{defaults[activeList]}</strong></div>
        )}
        {displayRules.map((rule) => (
          editingRule?.id === rule.id
            ? (
              <div key={rule.id}>
                <RuleForm
                  initial={editingRule}
                  listName={activeList}
                  onSave={handleUpdate}
                  onCancel={() => setEditingRule(null)}
                />
              </div>
            )
            : (
              <div
                key={rule.id}
                draggable
                onDragStart={() => handleDragStart(rule.id)}
                onDragEnd={handleDragEnd}
                onDragOver={e => handleDragOver(e, rule.id)}
                onDrop={() => handleDrop(rule.id)}
                className={dragOver === rule.id ? 'ring-2 ring-[var(--accent)] rounded-2xl' : ''}
              >
                <RuleRow
                  rule={rule}
                  onDelete={handleDelete}
                  onEdit={r => { setEditingRule(r); setShowForm(false); }}
                  dragHandleProps={{ draggable: false }}
                />
              </div>
            )
        ))}

        {showForm && (
          <RuleForm
            listName={activeList}
            onSave={handleCreate}
            onCancel={() => setShowForm(false)}
          />
        )}
      </section>

      {/* Actions */}
      <div className="flex gap-2">
        {!showForm && (
          <button type="button" onClick={() => { setShowForm(true); setEditingRule(null); }} className="primary-button">
            <Plus size={16} /><span>Add {activeList} rule</span>
          </button>
        )}
        {orderedIds && (
          <button type="button" onClick={saveOrder} className="primary-button">
            <span>Save rule order</span>
          </button>
        )}
        {orderedIds && (
          <button type="button" onClick={() => setOrderedIds(null)} className="ghost-button">
            <span>Discard order</span>
          </button>
        )}
      </div>
    </div>
  );
}
