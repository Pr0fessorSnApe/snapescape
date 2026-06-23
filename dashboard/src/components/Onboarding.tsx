import { useState } from 'react';

export function OnboardingWizard({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState(0);
  const steps = [
    { title: 'Welcome to SNAPESCAPE', body: 'The world\'s most advanced attack surface intelligence platform. Hunt bugs like a pro — in 3 clicks.', icon: '🛡️' },
    { title: 'Step 1: Enter Target', body: 'Type any domain you have permission to test. Example: target.com', icon: '🎯' },
    { title: 'Step 2: Pick Profile', body: 'Quick = fast recon. Standard = bug bounty ready. Deep = full arsenal.', icon: '⚡' },
    { title: 'Step 3: Launch & Hunt', body: 'Hit Launch Scan. Findings appear live. Click any finding for AI explanation + replay.', icon: '🚀' },
  ];
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div className="glass" style={{ maxWidth: 480, padding: 40, textAlign: 'center' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>{steps[step].icon}</div>
        <h2 style={{ fontFamily: 'Orbitron', color: '#00f0ff', marginBottom: 12 }}>{steps[step].title}</h2>
        <p style={{ color: '#aaa', lineHeight: 1.6, marginBottom: 24 }}>{steps[step].body}</p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
          {step > 0 && <button onClick={() => setStep(s => s - 1)} style={btnSecondary}>Back</button>}
          {step < steps.length - 1 ? (
            <button onClick={() => setStep(s => s + 1)} style={btnPrimary}>Next</button>
          ) : (
            <button onClick={() => { localStorage.setItem('snapescape_onboarded', '1'); onComplete(); }} style={btnPrimary}>
              Start Hunting
            </button>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginTop: 20 }}>
          {steps.map((_, i) => (
            <div key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: i === step ? '#00f0ff' : '#333' }} />
          ))}
        </div>
      </div>
    </div>
  );
}

export function QuickHuntBar({ onScan, loading }: {
  onScan: (target: string, profile: string) => void;
  loading: boolean;
}) {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('standard');

  return (
    <div className="glass" style={{ padding: 24, marginBottom: 16 }}>
      <h2 style={{ fontFamily: 'Orbitron', color: '#00f0ff', fontSize: 18, marginBottom: 4 }}>Quick Hunt</h2>
      <p style={{ color: '#666', fontSize: 13, marginBottom: 16 }}>Enter a target domain and launch — that's it.</p>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && target && onScan(target, profile)}
          placeholder="target.com"
          style={{
            flex: 1, minWidth: 200, background: '#0006', border: '1px solid #00f0ff33',
            borderRadius: 10, padding: '14px 18px', color: '#fff', fontSize: 16, fontFamily: 'JetBrains Mono',
          }}
        />
        <div style={{ display: 'flex', gap: 6 }}>
          {(['quick', 'standard', 'deep'] as const).map(p => (
            <button key={p} onClick={() => setProfile(p)} style={{
              padding: '10px 16px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontFamily: 'Orbitron',
              border: `1px solid ${profile === p ? '#00f0ff' : '#333'}`,
              background: profile === p ? '#00f0ff18' : 'transparent',
              color: profile === p ? '#00f0ff' : '#666',
            }}>
              {p === 'quick' ? '⚡ Quick' : p === 'standard' ? '🎯 Standard' : '🔥 Deep'}
            </button>
          ))}
        </div>
        <button
          onClick={() => target && onScan(target, profile)}
          disabled={loading || !target.trim()}
          style={{
            padding: '14px 28px', borderRadius: 10, cursor: loading ? 'wait' : 'pointer',
            background: 'linear-gradient(135deg, #00f0ff44, #7b2fff44)',
            border: '1px solid #00f0ff', color: '#00f0ff', fontWeight: 700, fontSize: 15, fontFamily: 'Orbitron',
            opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? 'Hunting...' : '🚀 Launch Scan'}
        </button>
      </div>
    </div>
  );
}

const btnPrimary: React.CSSProperties = {
  padding: '12px 28px', background: 'linear-gradient(135deg,#00f0ff33,#7b2fff33)',
  border: '1px solid #00f0ff', color: '#00f0ff', borderRadius: 8, cursor: 'pointer', fontFamily: 'Orbitron',
};
const btnSecondary: React.CSSProperties = {
  padding: '12px 28px', background: 'transparent', border: '1px solid #444',
  color: '#888', borderRadius: 8, cursor: 'pointer',
};
