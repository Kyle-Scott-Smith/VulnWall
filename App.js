import { useState, useRef, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
 
const vulnData = [ //Sample data
  { month: "Jan", count: 16 },
  { month: "Feb", count: 13 },
  { month: "Mar", count: 20 },
  { month: "Apr", count: 18 },
  { month: "May", count: 23 },
];
 
const activityItems = [ //Sample data
  { label: "3 new scans processed", tag: "Scan", color: "#2563eb", bg: "#eff6ff" },
  { label: "5 tickets created", tag: "Ticket", color: "#7c3aed", bg: "#f5f3ff" },
  { label: "2 tickets closed", tag: "Resolved", color: "#16a34a", bg: "#f0fdf4" },
  { label: "Critical vulnerabilities in API Gateway", tag: "Critical", color: "#dc2626", bg: "#fef2f2" },
];
 
const style = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap'); /*nicer font*/
 
  * { box-sizing: border-box; margin: 0; padding: 0; }
 
  html, body { height: 100%; }
 
  body { 
    font-family: 'DM Sans', sans-serif;
    background: #f0f2f7;
    height: 100%;
    padding: 24px;
    display: flex;
    flex-direction: column;
  }
 
  #root {
    flex: 1;
    display: flex;
    flex-direction: column;
  }
 
  .shell {
    background: #f0f2f7;
    width: 100%;
    padding: 16px;
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
 
  /*nav bar*/
  .nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding: 0 4px;
    flex-wrap: wrap;
    gap: 8px;
    flex-shrink: 0;
  }
  .nav-links {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }
  .nav-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: 20px;
    border: none;
    background: transparent;
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    font-weight: 500;
    color: #666;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .nav-btn:hover {
    background: rgba(0,0,0,0.05);
    color: #333;
  }
  .nav-btn.active {
    background: #2563eb;
    color: #fff;
  }
  .nav-btn .star {
    font-size: 13px;
  }
  .avatar {
    width: 34px; height: 34px;
    border-radius: 50%;
    background: #d1d5db;
    display: flex; align-items: center; justify-content: center;
    color: #6b7280;
    cursor: pointer;
    flex-shrink: 0;
  }
 
  /*heading*/
  .heading {
    margin-bottom: 16px;
    padding: 0 4px;
    flex-shrink: 0;
  }
  .heading h1 {
    font-size: clamp(16px, 2.5vw, 22px);
    font-weight: 700;
    color: #111;
  }
  .heading-sub {
    font-size: clamp(11px, 1.4vw, 13px);
    color: #6b7280;
    margin-top: 2px;
    display: flex; align-items: center; gap: 4px;
    cursor: pointer;
  }
  .heading-sub:hover {
    color: #374151;
  }
 
  /*stats*/
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 12px;
    flex-shrink: 0;
  }
  .stat-card {
    background: #fff;
    border-radius: 16px;
    padding: 18px 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    min-width: 0;
  }
  .stat-label { font-size: clamp(11px, 1.4vw, 13px);
    color: #6b7280;
    font-weight: 500;
    margin-bottom: 10px;
  }
  .stat-value {
    font-family: 'DM Mono', monospace;
    font-size: clamp(22px, 3.5vw, 32px);
    font-weight: 500;
    color: #111;
    display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap;
  }
  .stat-delta {
    font-size: clamp(11px, 1.4vw, 13px);
    font-weight: 600; color: #ef4444;
  }
  .stat-value.critical {
    color: #ef4444;
  }
  .stat-value.medium {
    color: #f97316;
  }
 
  /*middle row*/
  .mid-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 12px;
    flex: 1;
    min-height: 0;
  }

   /*chart*/
  .chart-card {
    background: #fff;
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .chart-title {
    font-size: clamp(12px, 1.5vw, 14px);
    font-weight: 600; color: #374151;
    margin-bottom: 16px; flex-shrink: 0;
  }
  .chart-grow {
    flex: 1;
    min-height: 0;
  }

  /*insight*/
  .insight-card {
    background: #dbeafe;
    border-radius: 16px;
    padding: 20px 24px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-width: 0;
  }
  .insight-label {
    font-size: clamp(11px, 1.4vw, 13px);
    font-weight: 700;
    color: #1d4ed8;
    margin-bottom: 0;
    letter-spacing: 0.02em;
    align-self: flex-start;
  }
  .insight-text {
    font-size: clamp(13px, 1.8vw, 18px);
    font-weight: 500; color: #1e40af;
    line-height: 1.5; text-align:
    center; flex: 1; display: flex;
    align-items: center;
    justify-content: center;
  }
 
  /*activity*/
  .activity-card {
    background: #fff;
    border-radius: 16px;
    padding: 18px 24px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    flex-shrink: 0;
  }
  .activity-title {
    font-size: clamp(12px, 1.5vw, 14px);
    font-weight: 600;
    color: #374151;
    margin-bottom: 14px;
  }
  .activity-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
  }
  .activity-item {
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
  }
  .activity-tag {
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
  }
  .activity-label {
    font-size: clamp(12px, 1.3vw, 13px);
    font-weight: 500;
    color: #374151;
    line-height: 1.4;
  }
 
  /*chat bubble*/
  .chat-bubble {
    position: fixed;
    bottom: 28px; right: 28px;
    width: 44px; height: 44px;
    border-radius: 50%;
    background: #7c3aed;
    display: flex; align-items: center; justify-content: center;
    color: white;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(124,58,237,0.45);
    font-size: 20px;
    z-index: 100;
  }
 
  /*Responsive*/
  @media (max-width: 700px) {
    body { padding: 12px; }
    .stats-row { grid-template-columns: repeat(2, 1fr); }
    .mid-row { grid-template-columns: 1fr; }
    .activity-grid { grid-template-columns: repeat(2, 1fr); }
  }
  @media (max-width: 400px) {
    .stats-row { grid-template-columns: 1fr 1fr; gap: 8px; }
    .stat-card { padding: 12px; }
    .activity-grid { grid-template-columns: 1fr 1fr; }
  }
`;
 
//Dashboard main definition
export default function SecurityDashboard() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const chartWrapRef = useRef(null);
  const [chartHeight, setChartHeight] = useState(180);
 
  useEffect(() => { //Dynamic growth
    if (!chartWrapRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        setChartHeight(entry.contentRect.height);
      }
    });
    ro.observe(chartWrapRef.current);
    return () => ro.disconnect();
  }, []);
 
  return (
    <>
      <style>{style}</style>
      <div className="shell">
        {/*Nav bar*/}
        <nav className="nav">
          <div className="nav-links">
            {["dashboard", "upload-scan", "tickets"].map((tab) => (
              <button
                key={tab}
                className={`nav-btn ${activeTab === tab ? "active" : ""}`}
                onClick={() => setActiveTab(tab)}
              >
                <span className="star">✦</span> {/*similar to fidelity*/}
                {tab === "dashboard" ? "Dashboard" : tab === "upload-scan" ? "Upload Scan" : "Tickets"}
              </button>
            ))}
          </div>
          <div className="avatar">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
              <circle cx="12" cy="7" r="4"/>
            </svg>
          </div>
        </nav>
 
        {/*Heading*/}
        <div className="heading">
          <h1>Security Overview</h1>
          <div className="heading-sub">Last 7 days ▾</div>
        </div>
 
        {/*Stats*/}
        <div className="stats-row">
          <div className="stat-card">
            <div className="stat-label">Total Vulnerabilities</div>
            <div className="stat-value">47 <span className="stat-delta">+9%</span></div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Critical</div>
            <div className="stat-value critical">8</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Medium</div>
            <div className="stat-value medium">13</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">New Today</div>
            <div className="stat-value">6</div>
          </div>
        </div>
 
        {/*Middle*/}
        <div className="mid-row">

          {/*Chart*/}
          <div className="chart-card">
            <div className="chart-title">Vulnerabilities over time</div>
            <div className="chart-grow" ref={chartWrapRef}>
              <ResponsiveContainer width="100%" height={chartHeight}>
                <BarChart data={vulnData} barSize={28}>
                  <CartesianGrid vertical={false} stroke="#f3f4f6" />
                  <XAxis dataKey="month" axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: "#9ca3af" }} />
                  <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "#9ca3af" }} domain={[0, 30]} ticks={[0, 10, 20, 30]} />
                  <Tooltip
                    cursor={{ fill: "rgba(37,99,235,0.08)" }}
                    contentStyle={{ borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,0.1)", fontSize: 13 }}
                  />
                  <Bar dataKey="count" fill="#2563eb" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>


          {/*Insight*/}
          <div className="insight-card">
            <div className="insight-label">AI Insight</div>
            <div className="insight-text"> 
              {/* Sample text */}
              Most critical issues affect external services. Consider prioritizing API Gateway and authentication layer patches.
            </div>
          </div>
        </div>
 
        {/*Activity*/}
        <div className="activity-card">
          <div className="activity-title">Recent Activity</div>
          <div className="activity-grid">
            {activityItems.map((item, i) => (
              <div key={i} className="activity-item" style={{ background: item.bg }}>
                <span className="activity-tag" style={{ color: item.color }}>
                  {item.tag}
                </span>
                <div className="activity-label">{item.label}</div>
              </div>
            ))}
          </div>
        </div>
 
        {/*Chat bubble*/}
        <div className="chat-bubble">💬</div> {/*looks better than I thought*/}
      </div>
    </>
  );
}
