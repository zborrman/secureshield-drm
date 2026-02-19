'use client';
import { useState, useEffect } from 'react';

export default function StatusIndicator({ service }: { service: string }) {
  const [status, setStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  useEffect(() => {
    const checkStatus = async () => {
      try {
        // Вызываем эндпоинт бэкенда, который проверяет соединение с БД
        const res = await fetch(`http://localhost:8000/health`);
        if (res.ok) setStatus('online');
        else setStatus('offline');
      } catch {
        setStatus('offline');
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 10000); // Проверка каждые 10 секунд
    return () => clearInterval(interval);
  }, [service]);

  return (
    <div className="flex items-center gap-2 px-2 py-1">
      <div className={`w-2 h-2 rounded-full shadow-[0_0_8px] ${
        status === 'online'  ? 'bg-brand-success shadow-green-500' :
        status === 'offline' ? 'bg-brand-error shadow-red-500' : 'bg-slate-500'
      }`} />
      <span className="text-[10px] font-mono uppercase tracking-tighter text-text-muted">
        {service}: {status}
      </span>
    </div>
  );
}
