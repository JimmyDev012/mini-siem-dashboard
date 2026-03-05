import { useState, useEffect } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from "recharts";
import {
  Shield, AlertTriangle, Activity, FileText, ChevronRight, Clock,
  User, Tag, Search, Download, Plus, X, Check, Filter, Terminal,
  Globe, Lock, Cpu, ChevronDown, ChevronUp, AlertCircle, CheckCircle,
  Eye, Layers
} from "lucide-react";
import {
  allAlerts, timelineData, topIPs, initialCases, windowsEvents, apacheLogs, sshLogs
} from "./data/logs.js";

// ─── Utility helpers ──────────────────────────────────────────────────────────
const SEV_COLOR = { critical: "#ff3b6b", high: "#ff8c42", medium: "#ffd166", low: "#06d6a0" };
const SEV_BG    = { critical: "#ff3b6b22", high: "#ff8c4222", medium: "#ffd16622", low: "#06d6a022" };
const STATUS_COLOR = { Open: "#ff8c42", Investigating: "#ffd166", Closed: "#06d6a0" };

const fmt = (iso) => {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) +
    " · " + d.toLocaleDateString([], { month: "short", day: "numeric" });
};

const Badge = ({ text, color }) => (
  <span style={{
    background: color + "22", color, border: `1px solid ${color}44`,
    borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 700,
    letterSpacing: "0.05em", textTransform: "uppercase", fontFamily: "monospace"
  }}>{text}</span>
);

const StatCard = ({ icon: Icon, label, value, sub, color }) => (
  <div style={{
    background: "#0d1117", border: "1px solid #21262d", borderRadius: 10,
    padding: "18px 22px", display: "flex", flexDirection: "column", gap: 8,
    borderLeft: `3px solid ${color}`, minWidth: 0
  }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#8b949e", fontSize: 12 }}>
      <Icon size={14} color={color} />{label}
    </div>
    <div style={{ fontSize: 32, fontWeight: 800, color, fontFamily: "monospace" }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: "#8b949e" }}>{sub}</div>}
  </div>
);

// ─── PDF Export ───────────────────────────────────────────────────────────────
const exportPDF = (caseItem, alerts) => {
  const linked = alerts.filter(a => caseItem.alerts.includes(a.id));
  const win = window.open("", "_blank");
  win.document.write(`
    <html><head><title>IR Report - ${caseItem.id}</title>
    <style>
      body { font-family: monospace; background: #fff; color: #111; padding: 40px; max-width: 800px; margin: 0 auto; }
      h1 { color: #c9282d; border-bottom: 2px solid #c9282d; padding-bottom: 10px; }
      h2 { color: #333; margin-top: 30px; border-left: 4px solid #c9282d; padding-left: 12px; }
      table { width: 100%; border-collapse: collapse; margin-top: 10px; }
      th { background: #f3f3f3; text-align: left; padding: 8px; font-size: 12px; }
      td { padding: 8px; border-bottom: 1px solid #eee; font-size: 12px; }
      .badge { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
      .critical { background: #ffe0e0; color: #c9282d; }
      .high { background: #fff3e0; color: #e65100; }
      .note { background: #f9f9f9; padding: 10px; margin: 8px 0; border-left: 3px solid #ccc; }
      .meta { color: #666; font-size: 11px; }
    </style></head><body>
    <h1>🛡 Incident Response Report</h1>
    <p class="meta">Generated: ${new Date().toISOString()} | Platform: Mini SIEM v1.0</p>
    <h2>Case Summary</h2>
    <table>
      <tr><th>Case ID</th><td>${caseItem.id}</td><th>Severity</th><td><span class="badge ${caseItem.severity}">${caseItem.severity.toUpperCase()}</span></td></tr>
      <tr><th>Title</th><td colspan="3">${caseItem.title}</td></tr>
      <tr><th>Status</th><td>${caseItem.status}</td><th>Analyst</th><td>${caseItem.analyst}</td></tr>
      <tr><th>Created</th><td>${caseItem.created}</td><th>Updated</th><td>${caseItem.updated}</td></tr>
    </table>
    <h2>MITRE ATT&CK Mapping</h2>
    <p>${caseItem.mitre.map(m => `<span class="badge high">${m}</span>`).join(" ")}</p>
    <h2>Linked Alerts (${linked.length})</h2>
    <table><tr><th>Time</th><th>Source</th><th>IP</th><th>Event</th><th>Severity</th></tr>
    ${linked.map(a => `<tr>
      <td>${a.timestamp}</td>
      <td>${a.source}</td>
      <td>${a.ip}</td>
      <td>${a.eventName || a.url || a.details?.slice(0, 50)}</td>
      <td><span class="badge ${a.level}">${a.level.toUpperCase()}</span></td>
    </tr>`).join("")}
    </table>
    <h2>Timeline of Notes</h2>
    ${caseItem.notes.map(n => `<div class="note"><strong>${n.author}</strong> <span class="meta">${n.time}</span><br/>${n.text}</div>`).join("")}
    <br/><hr/><p class="meta">CONFIDENTIAL — For authorized personnel only. Mini SIEM SOC Platform.</p>
    </body></html>
  `);
  win.document.close();
  win.print();
};

// ─── ALERT ROW ─────────────────────────────────────────────────────────────────
const AlertRow = ({ alert, onClick }) => (
  <div onClick={() => onClick(alert)} style={{
    display: "grid", gridTemplateColumns: "90px 80px 130px 1fr 160px 90px",
    gap: 12, padding: "10px 16px", borderBottom: "1px solid #21262d",
    cursor: "pointer", alignItems: "center",
    transition: "background 0.15s"
  }}
    onMouseEnter={e => e.currentTarget.style.background = "#161b22"}
    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
  >
    <Badge text={alert.level} color={SEV_COLOR[alert.level]} />
    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#8b949e" }}>
      {alert.eventId || alert.status || alert.method}
    </span>
    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#58a6ff" }}>{alert.ip}</span>
    <span style={{ fontSize: 12, color: "#c9d1d9", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
      {alert.eventName || alert.url || alert.details?.slice(0, 60)}
    </span>
    <span style={{
      fontSize: 11, color: "#ffd166", background: "#ffd16611",
      padding: "2px 6px", borderRadius: 4, fontFamily: "monospace"
    }}>
      {alert.mitre.id} · {alert.mitre.name}
    </span>
    <span style={{ fontSize: 11, color: "#8b949e" }}>{fmt(alert.timestamp)}</span>
  </div>
);

// ─── ALERT DETAIL MODAL ────────────────────────────────────────────────────────
const AlertModal = ({ alert, onClose }) => {
  if (!alert) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, background: "#00000088", zIndex: 100,
      display: "flex", alignItems: "center", justifyContent: "center"
    }} onClick={onClose}>
      <div style={{
        background: "#0d1117", border: "1px solid #30363d", borderRadius: 12,
        padding: 28, width: 560, maxHeight: "80vh", overflowY: "auto"
      }} onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: 20 }}>
          <div>
            <Badge text={alert.level} color={SEV_COLOR[alert.level]} />
            <h3 style={{ color: "#e6edf3", margin: "8px 0 4px", fontSize: 16 }}>
              {alert.eventName || alert.url || "Log Event"}
            </h3>
            <span style={{ fontSize: 11, color: "#8b949e" }}>{alert.source} · {alert.timestamp}</span>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#8b949e", cursor: "pointer" }}>
            <X size={18} />
          </button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
          {[
            ["Source IP", alert.ip],
            ["Host", alert.computer || "-"],
            ["User", alert.user || "-"],
            ["Event ID", alert.eventId || alert.method || "-"],
            ["Count", alert.count],
            ["Status", alert.status || alert.level],
          ].map(([k, v]) => (
            <div key={k} style={{ background: "#161b22", borderRadius: 6, padding: "10px 14px" }}>
              <div style={{ fontSize: 10, color: "#8b949e", marginBottom: 4 }}>{k}</div>
              <div style={{ fontSize: 13, color: "#e6edf3", fontFamily: "monospace" }}>{v}</div>
            </div>
          ))}
        </div>
        <div style={{ background: "#161b22", borderRadius: 6, padding: 14, marginBottom: 16 }}>
          <div style={{ fontSize: 10, color: "#8b949e", marginBottom: 6 }}>RAW DETAILS</div>
          <div style={{ fontSize: 12, color: "#c9d1d9", fontFamily: "monospace", lineHeight: 1.7 }}>
            {alert.details || `${alert.method} ${alert.url} HTTP/1.1 → ${alert.status} (${alert.bytes} bytes)\nUser-Agent: ${alert.userAgent}`}
          </div>
        </div>
        <div style={{
          background: "#ffd16611", border: "1px solid #ffd16633", borderRadius: 8, padding: 14
        }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
            <Tag size={13} color="#ffd166" />
            <span style={{ fontSize: 11, color: "#ffd166", fontWeight: 700 }}>MITRE ATT&CK</span>
          </div>
          <div style={{ fontFamily: "monospace", color: "#ffd166", fontSize: 14, fontWeight: 700 }}>{alert.mitre.id}</div>
          <div style={{ color: "#e6edf3", fontSize: 13 }}>{alert.mitre.name}</div>
          <div style={{ color: "#8b949e", fontSize: 11, marginTop: 4 }}>Tactic: {alert.mitre.tactic}</div>
        </div>
      </div>
    </div>
  );
};

// ─── CASE CARD ─────────────────────────────────────────────────────────────────
const CaseCard = ({ c, onOpen }) => (
  <div style={{
    background: "#0d1117", border: `1px solid #21262d`,
    borderLeft: `3px solid ${SEV_COLOR[c.severity]}`,
    borderRadius: 8, padding: 18, cursor: "pointer",
    transition: "border-color 0.15s"
  }}
    onMouseEnter={e => e.currentTarget.style.background = "#161b22"}
    onMouseLeave={e => e.currentTarget.style.background = "#0d1117"}
    onClick={() => onOpen(c)}
  >
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: 10 }}>
      <span style={{ fontFamily: "monospace", fontSize: 11, color: "#58a6ff" }}>{c.id}</span>
      <div style={{ display: "flex", gap: 8 }}>
        <Badge text={c.severity} color={SEV_COLOR[c.severity]} />
        <Badge text={c.status} color={STATUS_COLOR[c.status]} />
      </div>
    </div>
    <div style={{ color: "#e6edf3", fontSize: 14, fontWeight: 600, marginBottom: 8 }}>{c.title}</div>
    <div style={{ display: "flex", gap: 16, fontSize: 11, color: "#8b949e" }}>
      <span><User size={11} style={{ marginRight: 4 }} />{c.analyst}</span>
      <span><Clock size={11} style={{ marginRight: 4 }} />{fmt(c.updated)}</span>
      <span><AlertTriangle size={11} style={{ marginRight: 4 }} />{c.alerts.length} alerts</span>
    </div>
    <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap" }}>
      {c.mitre.map(m => (
        <span key={m} style={{
          background: "#ffd16611", color: "#ffd166", border: "1px solid #ffd16633",
          borderRadius: 4, padding: "1px 6px", fontSize: 10, fontFamily: "monospace"
        }}>{m}</span>
      ))}
    </div>
  </div>
);

// ─── CASE DETAIL MODAL ─────────────────────────────────────────────────────────
const CaseModal = ({ c, onClose, allAlerts }) => {
  const [note, setNote] = useState("");
  const [notes, setNotes] = useState(c.notes);

  if (!c) return null;
  const linked = allAlerts.filter(a => c.alerts.includes(a.id));

  const addNote = () => {
    if (!note.trim()) return;
    setNotes(prev => [...prev, {
      time: new Date().toISOString(), author: "Analyst", text: note
    }]);
    setNote("");
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "#00000099", zIndex: 100,
      display: "flex", alignItems: "center", justifyContent: "center", padding: 24
    }} onClick={onClose}>
      <div style={{
        background: "#0d1117", border: "1px solid #30363d", borderRadius: 12,
        padding: 28, width: 700, maxHeight: "90vh", overflowY: "auto"
      }} onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <span style={{ fontFamily: "monospace", fontSize: 12, color: "#58a6ff" }}>{c.id}</span>
            <h2 style={{ color: "#e6edf3", margin: "6px 0 8px", fontSize: 18 }}>{c.title}</h2>
            <div style={{ display: "flex", gap: 8 }}>
              <Badge text={c.severity} color={SEV_COLOR[c.severity]} />
              <Badge text={c.status} color={STATUS_COLOR[c.status]} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "start" }}>
            <button onClick={() => exportPDF(c, allAlerts)} style={{
              background: "#21262d", border: "1px solid #30363d", borderRadius: 6,
              padding: "6px 14px", color: "#c9d1d9", cursor: "pointer", fontSize: 12,
              display: "flex", gap: 6, alignItems: "center"
            }}>
              <Download size={13} /> Export PDF
            </button>
            <button onClick={onClose} style={{ background: "none", border: "none", color: "#8b949e", cursor: "pointer" }}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Meta */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10, marginBottom: 20 }}>
          {[["Analyst", c.analyst], ["Created", fmt(c.created)], ["Updated", fmt(c.updated)]].map(([k, v]) => (
            <div key={k} style={{ background: "#161b22", borderRadius: 6, padding: 12 }}>
              <div style={{ fontSize: 10, color: "#8b949e", marginBottom: 4 }}>{k}</div>
              <div style={{ fontSize: 13, color: "#e6edf3", fontFamily: "monospace" }}>{v}</div>
            </div>
          ))}
        </div>

        {/* MITRE */}
        <div style={{ background: "#ffd16608", border: "1px solid #ffd16622", borderRadius: 8, padding: 14, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#ffd166", fontWeight: 700, marginBottom: 8 }}>⚔️ MITRE ATT&CK COVERAGE</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {c.mitre.map(m => (
              <span key={m} style={{
                background: "#ffd16622", color: "#ffd166", border: "1px solid #ffd16644",
                borderRadius: 4, padding: "3px 10px", fontSize: 12, fontFamily: "monospace", fontWeight: 700
              }}>{m}</span>
            ))}
          </div>
        </div>

        {/* Alerts */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 10 }}>
            LINKED ALERTS ({linked.length})
          </div>
          {linked.map(a => (
            <div key={a.id} style={{
              display: "flex", gap: 12, padding: "8px 12px", background: "#161b22",
              borderRadius: 6, marginBottom: 6, alignItems: "center"
            }}>
              <Badge text={a.level} color={SEV_COLOR[a.level]} />
              <span style={{ fontFamily: "monospace", fontSize: 11, color: "#58a6ff" }}>{a.ip}</span>
              <span style={{ fontSize: 12, color: "#c9d1d9", flex: 1 }}>{a.eventName || a.url}</span>
              <span style={{ fontSize: 10, color: "#ffd166", fontFamily: "monospace" }}>{a.mitre.id}</span>
            </div>
          ))}
        </div>

        {/* Notes Timeline */}
        <div>
          <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 12 }}>NOTES TIMELINE</div>
          {notes.map((n, i) => (
            <div key={i} style={{ display: "flex", gap: 12, marginBottom: 14 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{
                  width: 28, height: 28, borderRadius: "50%", background: "#21262d",
                  display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                }}>
                  {n.author === "System" ? <Cpu size={12} color="#8b949e" /> : <User size={12} color="#58a6ff" />}
                </div>
                {i < notes.length - 1 && <div style={{ width: 1, flex: 1, background: "#21262d", margin: "4px 0" }} />}
              </div>
              <div style={{ flex: 1, paddingBottom: 4 }}>
                <div style={{ fontSize: 11, color: n.author === "System" ? "#8b949e" : "#58a6ff", marginBottom: 4 }}>
                  {n.author} · {fmt(n.time)}
                </div>
                <div style={{
                  background: "#161b22", borderRadius: 6, padding: "10px 14px",
                  fontSize: 13, color: "#c9d1d9", lineHeight: 1.6
                }}>{n.text}</div>
              </div>
            </div>
          ))}
          {/* Add note */}
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Add investigation note..."
              style={{
                flex: 1, background: "#161b22", border: "1px solid #30363d", borderRadius: 6,
                padding: "10px 12px", color: "#c9d1d9", fontSize: 13, resize: "none",
                height: 72, fontFamily: "inherit"
              }}
            />
            <button onClick={addNote} style={{
              background: "#1f6feb", border: "none", borderRadius: 6,
              padding: "0 18px", color: "#fff", cursor: "pointer", fontSize: 13, fontWeight: 600
            }}>Add</button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── MAIN APP ──────────────────────────────────────────────────────────────────
export default function SIEMDashboard() {
  const [tab, setTab] = useState("dashboard");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [cases, setCases] = useState(initialCases);
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setPulse(p => !p), 2000);
    return () => clearInterval(t);
  }, []);

  const critical = allAlerts.filter(a => a.level === "critical").length;
  const high = allAlerts.filter(a => a.level === "high").length;
  const totalEvents = allAlerts.reduce((s, a) => s + (a.count || 1), 0);

  const filtered = allAlerts.filter(a => {
    const q = search.toLowerCase();
    const matchSearch = !q || a.ip?.includes(q) || a.source?.toLowerCase().includes(q) ||
      a.eventName?.toLowerCase().includes(q) || a.url?.includes(q) || a.mitre?.id?.includes(q);
    const matchSev = sevFilter === "all" || a.level === sevFilter;
    return matchSearch && matchSev;
  });

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: Activity },
    { id: "alerts", label: "Alert Feed", icon: AlertTriangle },
    { id: "cases", label: "Case Management", icon: Layers },
  ];

  return (
    <div style={{
      background: "#010409", minHeight: "100vh", fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      color: "#e6edf3", display: "flex", flexDirection: "column"
    }}>
      {/* Top Bar */}
      <div style={{
        background: "#0d1117", borderBottom: "1px solid #21262d",
        padding: "0 24px", display: "flex", alignItems: "center", gap: 24, height: 52
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 8 }}>
          <div style={{ position: "relative" }}>
            <Shield size={20} color="#58a6ff" />
            <div style={{
              position: "absolute", top: -2, right: -2, width: 6, height: 6,
              borderRadius: "50%", background: pulse ? "#06d6a0" : "#06d6a088",
              transition: "background 0.5s"
            }} />
          </div>
          <span style={{ fontWeight: 800, fontSize: 15, letterSpacing: "0.05em", color: "#e6edf3" }}>
            MINI<span style={{ color: "#58a6ff" }}>SIEM</span>
          </span>
        </div>

        {navItems.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setTab(id)} style={{
            background: "none", border: "none", cursor: "pointer",
            padding: "0 4px", height: "100%",
            borderBottom: tab === id ? "2px solid #58a6ff" : "2px solid transparent",
            color: tab === id ? "#e6edf3" : "#8b949e",
            display: "flex", alignItems: "center", gap: 7, fontSize: 13,
            transition: "color 0.15s"
          }}>
            <Icon size={14} />{label}
          </button>
        ))}

        <div style={{ marginLeft: "auto", display: "flex", gap: 16, alignItems: "center" }}>
          <div style={{
            display: "flex", gap: 4, alignItems: "center",
            background: "#ff3b6b22", border: "1px solid #ff3b6b44",
            borderRadius: 6, padding: "4px 10px", fontSize: 12
          }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#ff3b6b", animation: "pulse 1s infinite" }} />
            <span style={{ color: "#ff3b6b", fontWeight: 700 }}>{critical} CRITICAL</span>
          </div>
          <span style={{ fontSize: 11, color: "#8b949e" }}>
            {new Date().toLocaleTimeString()} UTC
          </span>
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, padding: 24, maxWidth: 1400, margin: "0 auto", width: "100%" }}>

        {/* ── DASHBOARD TAB ── */}
        {tab === "dashboard" && (
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 20, color: "#e6edf3" }}>
              Security Overview <span style={{ fontSize: 13, color: "#8b949e", fontWeight: 400 }}>· Last 24 hours</span>
            </h1>

            {/* Stat Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 24 }}>
              <StatCard icon={AlertCircle} label="Critical Alerts" value={critical} sub="Requires immediate attention" color="#ff3b6b" />
              <StatCard icon={AlertTriangle} label="High Severity" value={high} sub="Active investigation" color="#ff8c42" />
              <StatCard icon={Activity} label="Total Events" value={totalEvents.toLocaleString()} sub="Across all log sources" color="#58a6ff" />
              <StatCard icon={Layers} label="Open Cases" value={cases.filter(c => c.status !== "Closed").length} sub={`${cases.length} total cases`} color="#06d6a0" />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20, marginBottom: 20 }}>
              {/* Timeline */}
              <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 16 }}>
                  EVENT TIMELINE — ALERT DENSITY BY HOUR
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timelineData} margin={{ top: 5, right: 10, bottom: 0, left: -10 }}>
                    <defs>
                      {[["critical", "#ff3b6b"], ["high", "#ff8c42"], ["medium", "#ffd166"]].map(([k, c]) => (
                        <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={c} stopOpacity={0.5} />
                          <stop offset="100%" stopColor={c} stopOpacity={0.02} />
                        </linearGradient>
                      ))}
                    </defs>
                    <XAxis dataKey="time" tick={{ fill: "#8b949e", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#8b949e", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 6, fontSize: 11 }} />
                    {[["critical", "#ff3b6b"], ["high", "#ff8c42"], ["medium", "#ffd166"]].map(([k, c]) => (
                      <Area key={k} type="monotone" dataKey={k} stroke={c} strokeWidth={2}
                        fill={`url(#g-${k})`} stackId="1" />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Top IPs */}
              <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 16 }}>
                  TOP OFFENDING IPs
                </div>
                {topIPs.map((ip, i) => (
                  <div key={i} style={{ marginBottom: 14 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, alignItems: "center" }}>
                      <div>
                        <span style={{ fontFamily: "monospace", fontSize: 12, color: "#58a6ff" }}>{ip.ip}</span>
                        <span style={{
                          marginLeft: 8, fontSize: 10, color: SEV_COLOR[ip.severity],
                          background: SEV_BG[ip.severity], padding: "1px 5px", borderRadius: 3
                        }}>{ip.label}</span>
                      </div>
                      <span style={{ fontFamily: "monospace", fontSize: 13, color: SEV_COLOR[ip.severity], fontWeight: 700 }}>
                        {ip.count}
                      </span>
                    </div>
                    <div style={{ background: "#21262d", borderRadius: 4, height: 5, overflow: "hidden" }}>
                      <div style={{
                        width: `${(ip.count / topIPs[0].count) * 100}%`,
                        height: "100%", background: SEV_COLOR[ip.severity],
                        borderRadius: 4, transition: "width 0.6s ease"
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Severity Bar + Log Sources */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 16 }}>ALERTS BY SEVERITY</div>
                <ResponsiveContainer width="100%" height={150}>
                  <BarChart data={[
                    { name: "Critical", count: critical, color: "#ff3b6b" },
                    { name: "High", count: high, color: "#ff8c42" },
                    { name: "Medium", count: allAlerts.filter(a => a.level === "medium").length, color: "#ffd166" },
                    { name: "Low", count: allAlerts.filter(a => a.level === "low").length, color: "#06d6a0" },
                  ]} margin={{ top: 5, right: 10, bottom: 0, left: -10 }}>
                    <XAxis dataKey="name" tick={{ fill: "#8b949e", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#8b949e", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 6, fontSize: 11 }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {[{ color: "#ff3b6b" }, { color: "#ff8c42" }, { color: "#ffd166" }, { color: "#06d6a0" }].map((e, i) => (
                        <Cell key={i} fill={e.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 12, color: "#8b949e", fontWeight: 700, marginBottom: 16 }}>LOG SOURCES</div>
                {[
                  { name: "Windows Security Events", count: windowsEvents.length, icon: "🪟", color: "#58a6ff" },
                  { name: "Apache Access Logs", count: apacheLogs.length, icon: "🌐", color: "#06d6a0" },
                  { name: "SSH Auth Logs", count: sshLogs.length, icon: "🔐", color: "#ffd166" },
                ].map((s, i) => (
                  <div key={i} style={{
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "10px 14px", background: "#161b22", borderRadius: 6, marginBottom: 8
                  }}>
                    <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                      <span>{s.icon}</span>
                      <span style={{ fontSize: 13, color: "#c9d1d9" }}>{s.name}</span>
                    </div>
                    <span style={{ fontFamily: "monospace", fontWeight: 700, color: s.color }}>{s.count} events</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── ALERT FEED TAB ── */}
        {tab === "alerts" && (
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: "#e6edf3" }}>
                Alert Feed <span style={{ fontSize: 13, color: "#8b949e", fontWeight: 400 }}>· {filtered.length} events</span>
              </h1>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{
                  display: "flex", alignItems: "center", gap: 8,
                  background: "#161b22", border: "1px solid #30363d", borderRadius: 6, padding: "0 12px"
                }}>
                  <Search size={13} color="#8b949e" />
                  <input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder="Search IP, event, MITRE ID..."
                    style={{
                      background: "none", border: "none", color: "#c9d1d9", fontSize: 12,
                      outline: "none", padding: "8px 0", width: 240, fontFamily: "monospace"
                    }} />
                </div>
                {["all", "critical", "high", "medium", "low"].map(s => (
                  <button key={s} onClick={() => setSevFilter(s)} style={{
                    background: sevFilter === s ? (SEV_COLOR[s] || "#21262d") + "33" : "#161b22",
                    border: `1px solid ${sevFilter === s ? (SEV_COLOR[s] || "#58a6ff") + "66" : "#30363d"}`,
                    borderRadius: 6, padding: "6px 12px",
                    color: SEV_COLOR[s] || "#8b949e", cursor: "pointer", fontSize: 11, fontWeight: 700
                  }}>{s.toUpperCase()}</button>
                ))}
              </div>
            </div>

            <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, overflow: "hidden" }}>
              <div style={{
                display: "grid", gridTemplateColumns: "90px 80px 130px 1fr 160px 90px",
                gap: 12, padding: "10px 16px", background: "#161b22",
                fontSize: 10, color: "#8b949e", fontWeight: 700, letterSpacing: "0.08em"
              }}>
                {["SEVERITY", "EVENT ID", "SOURCE IP", "DESCRIPTION", "MITRE ID", "TIME"].map(h => (
                  <span key={h}>{h}</span>
                ))}
              </div>
              {filtered.map(alert => (
                <AlertRow key={alert.id} alert={alert} onClick={setSelectedAlert} />
              ))}
              {filtered.length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: "#8b949e", fontSize: 13 }}>
                  No alerts match current filters.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── CASES TAB ── */}
        {tab === "cases" && (
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: "#e6edf3" }}>
                Case Management <span style={{ fontSize: 13, color: "#8b949e", fontWeight: 400 }}>· {cases.length} cases</span>
              </h1>
              <div style={{ display: "flex", gap: 16, fontSize: 12 }}>
                {["Open", "Investigating", "Closed"].map(s => (
                  <span key={s} style={{ color: STATUS_COLOR[s] }}>
                    ● {s}: {cases.filter(c => c.status === s).length}
                  </span>
                ))}
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 16 }}>
              {cases.map(c => <CaseCard key={c.id} c={c} onOpen={setSelectedCase} />)}
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      <AlertModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      {selectedCase && (
        <CaseModal c={selectedCase} onClose={() => setSelectedCase(null)} allAlerts={allAlerts} />
      )}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        textarea::placeholder, input::placeholder { color: #8b949e !important; }
      `}</style>
    </div>
  );
}
