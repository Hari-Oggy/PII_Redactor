import { useState, useEffect } from 'react';

// Theme for Premium UI
const Card = ({ children, title }: { children: React.ReactNode, title: string }) => (
  <div className="bg-gray-800 rounded-2xl shadow-xl overflow-hidden border border-gray-700 transition-all hover:border-gray-600">
    <div className="px-6 py-4 border-b border-gray-700 bg-gray-800/50 backdrop-blur-md">
      <h3 className="text-lg font-semibold text-gray-100">{title}</h3>
    </div>
    <div className="p-6">{children}</div>
  </div>
);

function App() {
  const [status, setStatus] = useState({ health: 'loading', ready: 'loading' });
  const [blocklist, setBlocklist] = useState<string[]>([]);
  const [newTerm, setNewTerm] = useState('');
  const [apiKey, setApiKey] = useState('admin-secret-key'); // Default from config
  const [notification, setNotification] = useState('');

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(''), 3000);
  };

  const fetchStatus = async () => {
    try {
      const h = await fetch('/healthz');
      const r = await fetch('/readyz');
      setStatus({ 
        health: h.ok ? 'alive' : 'down', 
        ready: r.ok ? 'ready' : 'not ready' 
      });
    } catch {
      setStatus({ health: 'down', ready: 'down' });
    }
  };

  const fetchBlocklist = async () => {
    try {
      const res = await fetch('/admin/blocklist', { headers: { 'X-Admin-Key': apiKey } });
      if (res.ok) {
        const data = await res.json();
        setBlocklist(data.blocklist || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const addToBlocklist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTerm) return;
    try {
      const res = await fetch('/admin/blocklist', {
        method: 'POST',
        headers: { 'X-Admin-Key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ terms: [newTerm] })
      });
      if (res.ok) {
        setNewTerm('');
        fetchBlocklist();
        showNotification('Term added to blocklist');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const clearBlocklist = async () => {
    try {
      const res = await fetch('/admin/blocklist', {
        method: 'DELETE',
        headers: { 'X-Admin-Key': apiKey }
      });
      if (res.ok) {
        fetchBlocklist();
        showNotification('Blocklist cleared');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const reloadConfig = async () => {
    try {
      const res = await fetch('/admin/config/reload', {
        method: 'POST',
        headers: { 'X-Admin-Key': apiKey }
      });
      if (res.ok) {
        showNotification('Configuration reloaded successfully');
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchBlocklist();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [apiKey]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-gray-100 p-8 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header Section */}
        <header className="flex justify-between items-center pb-6 border-b border-gray-700/50">
          <div>
            <h1 className="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-primary-500 to-purple-500">
              PII Redactor Gateway
            </h1>
            <p className="text-gray-400 mt-2">Zero-Trust Context-aware PII Detection Layer</p>
          </div>
          
          <div className="flex items-center gap-4">
            <div className={`px-4 py-2 rounded-full border flex items-center gap-2 backdrop-blur-md transition-colors ${
              status.health === 'alive' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'
            }`}>
              <div className={`w-2.5 h-2.5 rounded-full ${status.health === 'alive' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
              System: {status.health}
            </div>
            <div className={`px-4 py-2 rounded-full border flex items-center gap-2 backdrop-blur-md transition-colors ${
              status.ready === 'ready' ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
            }`}>
              <div className={`w-2.5 h-2.5 rounded-full ${status.ready === 'ready' ? 'bg-blue-500 animate-pulse' : 'bg-yellow-500'}`} />
              Ready: {status.ready}
            </div>
          </div>
        </header>

        {notification && (
          <div className="bg-primary-500/20 border border-primary-500/50 text-blue-300 px-6 py-3 rounded-xl animate-fade-in-down shadow-lg backdrop-blur-sm">
            {notification}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Main Controls */}
          <div className="lg:col-span-2 space-y-8">
            <Card title="Dynamic Blocklist Management">
               <div className="flex gap-4 mb-6">
                <form onSubmit={addToBlocklist} className="flex-1 flex gap-4">
                  <input 
                    type="text" 
                    value={newTerm}
                    onChange={(e) => setNewTerm(e.target.value)}
                    placeholder="Enter strict PII string to block..." 
                    className="flex-1 bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-gray-100 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 transition-all shadow-inner"
                  />
                  <button type="submit" className="bg-primary-500 hover:bg-blue-600 text-white px-6 py-3 rounded-xl font-medium transition-all shadow-lg hover:shadow-primary-500/25 active:scale-95">
                    Add Term
                  </button>
                </form>
                <button onClick={clearBlocklist} className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-6 py-3 rounded-xl font-medium transition-all focus:outline-none focus:ring-2 focus:ring-red-500/50 active:scale-95">
                  Clear All
                </button>
              </div>

              <div className="bg-gray-900 rounded-xl p-6 border border-gray-700 shadow-inner min-h-[200px]">
                {blocklist.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-2">
                    <svg className="w-12 h-12 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    <p>No blocked terms configured.</p>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-3">
                    {blocklist.map((term, i) => (
                      <span key={i} className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 flex items-center gap-2 group hover:border-gray-500 transition-colors cursor-default shadow-sm">
                        {term}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-8">
            <Card title="Gateway Controls">
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Admin API Key</label>
                  <input 
                    type="password" 
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-gray-100 focus:outline-none focus:border-primary-500 transition-all font-mono shadow-inner"
                  />
                </div>
                
                <button 
                  onClick={reloadConfig}
                  className="w-full bg-gray-700 hover:bg-gray-600 border border-gray-600 text-white px-4 py-3 rounded-xl font-medium transition-all shadow-md active:scale-95 flex items-center justify-center gap-2 group"
                >
                  <svg className="w-5 h-5 text-gray-400 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                  Hot-Reload Config
                </button>
              </div>
            </Card>

            <Card title="Traffic Policies">
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700/50">
                   <span className="text-gray-300">Phase 6 ML Sidecar</span>
                   <span className="px-2 py-1 bg-green-500/10 text-green-400 text-xs rounded border border-green-500/20">Active</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700/50">
                   <span className="text-gray-300">Policy Engine</span>
                   <span className="px-2 py-1 bg-green-500/10 text-green-400 text-xs rounded border border-green-500/20">RBAC Verified</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700/50">
                   <span className="text-gray-300">Token Map</span>
                   <span className="px-2 py-1 bg-purple-500/10 text-purple-400 text-xs rounded border border-purple-500/20">Redis Persistent</span>
                </div>
              </div>
            </Card>
          </div>
          
        </div>
      </div>
    </div>
  );
}

export default App;
