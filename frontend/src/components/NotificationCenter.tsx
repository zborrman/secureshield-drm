'use client';
import { useState, useEffect } from 'react';

export default function NotificationCenter() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isOpen, setIsOpen] = useState(false);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/admin/alerts');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (err) {
      console.error("Alert check failed");
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 15000); // Проверка каждые 15 сек
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative">
      {/* Иконка колокольчика */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-text-muted hover:text-brand-primary transition-colors"
      >
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {alerts.length > 0 && (
          <span className="absolute top-1 right-1 flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-error opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-brand-error"></span>
          </span>
        )}
      </button>

      {/* Выпадающее меню алертов */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 bg-brand-surface border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden">
          <div className="p-4 border-b border-slate-700 bg-black/20 flex justify-between items-center">
            <h3 className="text-xs font-bold uppercase tracking-widest text-text-main">Security Alerts</h3>
            <span className="text-[10px] bg-brand-error/20 text-brand-error px-2 py-0.5 rounded-full">
              {alerts.length} New
            </span>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="p-8 text-center text-text-muted text-xs italic">
                Система стабильна. Угроз не обнаружено.
              </div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="p-4 border-b border-slate-800 hover:bg-white/5 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="mt-1 w-2 h-2 rounded-full bg-brand-error shadow-[0_0_8px_#EF4444] shrink-0"></div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-text-main font-semibold">Подозрительная активность</p>
                      <p className="text-[10px] text-text-muted mt-1">
                        Неудачный вход: <span className="text-brand-primary font-mono">{alert.invoice_id}</span>
                      </p>
                      <div className="flex justify-between mt-2 items-center">
                        <span className="text-[9px] text-slate-500 font-mono">IP: {alert.ip_address}</span>
                        <span className="text-[9px] text-slate-500 italic">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="p-3 bg-black/10 text-center">
            <button className="text-[10px] text-brand-primary hover:underline uppercase font-bold">
              Открыть полный журнал аудита
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
